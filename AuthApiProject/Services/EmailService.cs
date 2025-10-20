
using MailKit.Net.Smtp;
using MimeKit;

namespace AuthApiProject.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendEmailAsync(string to, string subject, string htmlMessage)
        {

            var emailSettings = _config.GetSection("EmailSettings");
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(emailSettings["FromEmail"]!, emailSettings["FromEmail"]!));
            message.To.Add(new MailboxAddress(to, to));
            message.Subject = subject;

            var bodyBuilder = new BodyBuilder { HtmlBody = htmlMessage };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(emailSettings["SmtpHost"]!, int.Parse(emailSettings["SmtpPort"]!), MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(emailSettings["SmtpUser"]!, emailSettings["SmtpPass"]!);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }


    }
}
