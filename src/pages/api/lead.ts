import 'dotenv/config';
import type { APIRoute } from 'astro';
import nodemailer from 'nodemailer';

export const prerender = false;

// Helper to safely read env variables from import.meta.env or process.env
function getEnv(key: string, defaultValue = ''): string {
  const metaVal = (import.meta.env as Record<string, string | undefined>)?.[
    key
  ];
  const procVal = process.env[key];
  return (metaVal || procVal || defaultValue).trim();
}

function isPlaceholderValue(val: string): boolean {
  if (!val) return true;
  const v = val.toLowerCase().trim();
  return (
    v.includes('ваш_логин') ||
    v.includes('ваш_пароль') ||
    v.includes('пароль_приложения') ||
    v.includes('your_login') ||
    v.includes('your_app_password') ||
    v.includes('example.com')
  );
}

// Simple in-memory rate limiting: IP -> timestamp array
const ipRequests = new Map<string, number[]>();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX_REQUESTS = 5;

// Clean up old rate limit entries every 15 minutes
setInterval(
  () => {
    const now = Date.now();
    for (const [ip, timestamps] of ipRequests.entries()) {
      const valid = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
      if (valid.length === 0) {
        ipRequests.delete(ip);
      } else {
        ipRequests.set(ip, valid);
      }
    }
  },
  15 * 60 * 1000,
);

function sanitize(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export const POST: APIRoute = async ({ request, clientAddress }) => {
  try {
    const ip = clientAddress || 'unknown';

    // 1. Rate Limiting Check
    const now = Date.now();
    const timestamps = ipRequests.get(ip) || [];
    const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

    if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
      return new Response(
        JSON.stringify({
          success: false,
          error:
            'Слишком много запросов. Пожалуйста, подождите несколько минут перед повторной отправкой.',
        }),
        {
          status: 429,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    // 2. Parse request payload (supports both JSON and FormData)
    let name = '';
    let tel = '';
    let email = '';
    let message = '';
    let formTitle = 'Заявка с сайта';
    let honeypot = '';
    let formRenderTime = 0;

    const contentType = request.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
      const body = await request.json();
      name = body.name || '';
      tel = body.tel || '';
      email = body.email || '';
      message = body.message || '';
      formTitle = body.title || body.formTitle || 'Заявка с сайта';
      honeypot = body.website || body.hp_check || '';
      formRenderTime = Number(body._t || 0);
    } else {
      const formData = await request.formData();
      name = (formData.get('name') as string) || '';
      tel = (formData.get('tel') as string) || '';
      email = (formData.get('email') as string) || '';
      message = (formData.get('message') as string) || '';
      formTitle =
        (formData.get('title') as string) ||
        (formData.get('formTitle') as string) ||
        'Заявка с сайта';
      honeypot =
        (formData.get('website') as string) ||
        (formData.get('hp_check') as string) ||
        '';
      formRenderTime = Number(formData.get('_t') || 0);
    }

    // 3. Anti-Spam: Honeypot trap check
    // Real users never see or fill this hidden field; bots always fill it.
    if (honeypot && honeypot.trim().length > 0) {
      console.warn(
        `[Anti-Spam] Honeypot triggered from IP ${ip}. Silently ignored.`,
      );
      // Pretend success to fool bots without alerting them
      return new Response(
        JSON.stringify({ success: true, message: 'Заявка принята' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // 4. Anti-Spam: Time-based check (minimum 2.0 seconds needed for human submission)
    if (formRenderTime > 0) {
      const elapsed = now - formRenderTime;
      if (elapsed < 2000) {
        console.warn(
          `[Anti-Spam] Submission too fast (${elapsed}ms) from IP ${ip}. Rejected.`,
        );
        return new Response(
          JSON.stringify({
            success: false,
            error:
              'Обнаружена автоматическая отправка формы. Пожалуйста, заполните форму повторно.',
          }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        );
      }
    }

    // 5. Input Validation
    name = name.trim();
    tel = tel.trim();
    email = email.trim();
    message = message.trim();

    if (!name || name.length < 2) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Пожалуйста, укажите ваше имя (минимум 2 символа).',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const phoneDigits = tel.replace(/\D/g, '');
    if (!tel || phoneDigits.length < 7) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Пожалуйста, укажите корректный номер телефона.',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Пожалуйста, укажите корректный адрес электронной почты.',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // Record request timestamp for rate limiting
    recent.push(now);
    ipRequests.set(ip, recent);

    // 6. SMTP Email Dispatch to nice-dev@list.ru
    const recipient = getEnv('SMTP_TO', 'nice-dev@list.ru');
    const smtpHost = getEnv('SMTP_HOST', 'smtp.mail.ru');
    const smtpPort = Number(getEnv('SMTP_PORT', '465'));
    const smtpSecure = getEnv('SMTP_SECURE', 'true') !== 'false';
    const smtpUser = getEnv('SMTP_USER', '');
    const smtpPass = getEnv('SMTP_PASS', '');

    // For Mail.ru / Yandex, sender email in From header MUST match authenticated smtpUser
    let smtpFrom = getEnv('SMTP_FROM');
    if (
      !smtpFrom ||
      smtpFrom.includes('your_login') ||
      smtpFrom.includes('info@template-2.ru') ||
      smtpFrom.includes('ваш_логин')
    ) {
      smtpFrom = smtpUser
        ? `"Туристическое агентство template-2" <${smtpUser}>`
        : '"Туристическое агентство template-2" <info@template-2.ru>';
    }

    const submissionDate = new Date().toLocaleString('ru-RU', {
      timeZone: 'Europe/Moscow',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const safeName = sanitize(name);
    const safeTel = sanitize(tel);
    const safeEmail = sanitize(email);
    const safeMessage = sanitize(message || 'Не указан');
    const safeTitle = sanitize(formTitle);

    const emailSubject = `Новая заявка с сайта: ${safeTitle}`;

    const emailHtml = `
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>${emailSubject}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f8; margin: 0; padding: 20px; color: #333333; }
    .card { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.08); border: 1px solid #e1e4e8; }
    .header { background: #2F0391; padding: 24px 30px; color: #ffffff; }
    .header h1 { margin: 0; font-size: 20px; font-weight: 700; }
    .header p { margin: 6px 0 0; font-size: 13px; color: #CEDD04; text-transform: uppercase; letter-spacing: 0.5px; }
    .content { padding: 30px; }
    .table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .table tr td { padding: 12px 10px; border-bottom: 1px solid #f0f0f0; font-size: 14px; vertical-align: top; }
    .table tr td:first-child { width: 140px; font-weight: 600; color: #57595D; }
    .table tr td:last-child { color: #111111; }
    .badge { display: inline-block; background-color: #EDECEC; color: #2F0391; font-weight: 600; padding: 3px 8px; border-radius: 4px; font-size: 13px; }
    .message-box { background: #fafafa; border-left: 3px solid #2F0391; padding: 12px 15px; margin-top: 5px; font-style: italic; white-space: pre-wrap; }
    .footer { background: #f8f9fa; padding: 15px 30px; text-align: center; font-size: 12px; color: #888888; border-top: 1px solid #eaeaea; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>Новая заявка с сайта template-2</h1>
    </div>
    <div class="content">
      <table class="table">
        <tr>
          <td>Тема заявки:</td>
          <td><span class="badge">${safeTitle}</span></td>
        </tr>
        <tr>
          <td>Имя клиента:</td>
          <td><strong>${safeName}</strong></td>
        </tr>
        <tr>
          <td>Телефон:</td>
          <td><a href="tel:${safeTel}" style="color: #2F0391; font-weight: bold; text-decoration: none;">${safeTel}</a></td>
        </tr>
        <tr>
          <td>Электронная почта:</td>
          <td><a href="mailto:${safeEmail}" style="color: #2F0391; text-decoration: none;">${safeEmail}</a></td>
        </tr>
        <tr>
          <td>Комментарий:</td>
          <td><div class="message-box">${safeMessage}</div></td>
        </tr>
        <tr>
          <td>Дата и время (МСК):</td>
          <td>${submissionDate}</td>
        </tr>
        <tr>
          <td>IP-адрес:</td>
          <td><code>${ip}</code></td>
        </tr>
      </table>
    </div>
    <div class="footer">
      Письмо сформировано автоматически формой обратной связи template-2 и отправлено на адрес <strong>${recipient}</strong>.
    </div>
  </div>
</body>
</html>
    `;

    const emailText = `
Новая заявка с сайта template-2:
------------------------------------------
Тема: ${formTitle}
Имя: ${name}
Телефон: ${tel}
E-mail: ${email}
Комментарий: ${message || 'Не указан'}
Дата: ${submissionDate}
IP-адрес: ${ip}
------------------------------------------
Получатель: ${recipient}
    `;

    const hasCredentials = smtpUser.length > 0 && smtpPass.length > 0;
    const isPlaceholder =
      isPlaceholderValue(smtpUser) || isPlaceholderValue(smtpPass);

    if (!hasCredentials || isPlaceholder) {
      console.warn(
        `[SMTP Warning] Real SMTP credentials are not configured in .env.`,
      );
      console.warn(`[SMTP Lead captured]:\n${emailText}`);

      let errorMessage = 'Заявка не отправлена на почту: ';
      if (isPlaceholder) {
        errorMessage +=
          'в файле .env указаны шаблонные примеры (текст «ваш_логин@mail.ru» или «ваш_пароль_приложения»). Укажите ваш настоящий логин Mail.ru и пароль для внешних приложений, после чего перезапустите локальный сервер (Ctrl+C, затем npm run dev).';
      } else {
        errorMessage +=
          'в файле .env не заполнены параметры SMTP_USER или SMTP_PASS. Заполните их и обязательно перезапустите локальный сервер (Ctrl+C, затем npm run dev).';
      }

      return new Response(
        JSON.stringify({
          success: false,
          error: errorMessage,
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    // Production SMTP dispatch
    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });

    await transporter.sendMail({
      from: smtpFrom,
      to: recipient,
      replyTo: email,
      subject: emailSubject,
      text: emailText,
      html: emailHtml,
    });

    console.log(`[SMTP] Successfully dispatched email to ${recipient}`);

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Спасибо! Ваша заявка успешно отправлена.',
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  } catch (err: any) {
    console.error('[API Error /api/lead]:', err);

    const rawError = String(err?.message || err || '');
    let friendlyError =
      'Произошла ошибка при отправке заявки на почту. Пожалуйста, попробуйте позже или свяжитесь с нами по телефону.';

    if (
      rawError.includes('Invalid login') ||
      rawError.includes('authentication failed') ||
      rawError.includes('535')
    ) {
      friendlyError =
        'Ошибка авторизации Mail.ru (код 535): неверный логин или пароль. Внимание: в поле SMTP_PASS нужно указать специальный «Пароль для внешних приложений», созданный в настройках безопасности Mail.ru (а не обычный пароль от ящика).';
    } else if (
      rawError.includes('Sender address not accepted') ||
      rawError.includes('550') ||
      rawError.includes('not authorized')
    ) {
      friendlyError =
        'Ошибка почтового сервера Mail.ru (код 550): адрес отправителя должен совпадать с ящиком авторизации SMTP_USER.';
    } else if (
      rawError.includes('ECONNREFUSED') ||
      rawError.includes('ETIMEDOUT') ||
      rawError.includes('ENOTFOUND')
    ) {
      friendlyError =
        'Не удалось подключиться к почтовому серверу smtp.mail.ru (порт 465). Проверьте интернет-соединение или сетевой экран.';
    }

    return new Response(
      JSON.stringify({
        success: false,
        error: friendlyError,
      }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  }
};
