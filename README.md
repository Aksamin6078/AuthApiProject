# 🔐 ASP.NET Core Auth API

This is a secure authentication API built with ASP.NET Core 7, Identity, JWT, and Entity Framework Core. It includes features like user registration, login, password reset, email verification, and role-based authorization (Admin/User).

---

## 🚀 Features

- ✅ User Registration
- ✅ JWT Authentication (Access + Refresh Tokens)
- ✅ Role-based Authorization (Admin / User)
- ✅ Password Reset via Email
- ✅ Change Password
- ✅ Email Sending via SMTP
- ✅ Admin-only Endpoint to View All Users
- ✅ Swagger UI for Testing

---

## 🛠️ Tech Stack

- ASP.NET Core 7 Web API
- Entity Framework Core (SQL Server)
- Identity for authentication
- JWT (JSON Web Tokens)
- FluentValidation (optional)
- Swagger / Swashbuckle
- SMTP (Gmail) for sending emails

---

## 🧰 Requirements

- [.NET 7 SDK](https://dotnet.microsoft.com/en-us/download)
- SQL Server or LocalDB
- Visual Studio or VS Code
- Gmail (or SMTP credentials)

---

## ⚙️ Configuration

Update the `appsettings.json` file:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=(localdb)\\ProjectModels;Database=AuthApiDb;Trusted_Connection=True;"
},
"Jwt": {
  "Key": "<Your Secret Key>",
  "Issuer": "AuthApi",
  "Audience": "AuthApiUsers",
  "AccessTokenExpiryMinutes": "15",
  "RefreshTokenExpiryDays": "7"
},
"AdminSettings": {
  "Email": "admin@example.com",
  "Password": "Admin@123"
},
"EmailSettings": {
  "SmtpHost": "smtp.gmail.com",
  "SmtpPort": 587,
  "SmtpUser": "your-gmail@gmail.com",
  "SmtpPass": "your-app-password",
  "FromEmail": "your-gmail@gmail.com"
}
