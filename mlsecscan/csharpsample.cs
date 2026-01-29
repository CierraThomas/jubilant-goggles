/*
 INTENTIONALLY VULNERABLE TEST FILE
 ---------------------------------
 This file contains insecure coding patterns ON PURPOSE.
 DO NOT USE IN PRODUCTION.

 Used to validate mlsecscan C# analyzers and remediation logic.
*/

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableSamples
{
    public class AllVulnsController : Controller
    {
        // ------------------------------------------------------------------
        // Hard-coded secrets
        // ------------------------------------------------------------------

        private const string ApiKey = "TEST_ONLY_FAKE_API_KEY_123456";
        private const string DbPassword = "plaintext_password";

        // ------------------------------------------------------------------
        // SQL Injection
        // ------------------------------------------------------------------

        public IActionResult GetUser(string username)
        {
            var conn = new SqlConnection("Server=localhost;Database=Users;User Id=sa;Password=" + DbPassword);
            var cmd = new SqlCommand(
                "SELECT * FROM Users WHERE Name = '" + username + "'",
                conn
            );

            conn.Open();
            var reader = cmd.ExecuteReader();
            return Ok(reader);
        }

        // ------------------------------------------------------------------
        // Command Injection
        // ------------------------------------------------------------------

        public IActionResult Ping(string host)
        {
            Process.Start("cmd.exe", "/c ping " + host);
            return Ok();
        }

        // ------------------------------------------------------------------
        // Unsafe Deserialization
        // ------------------------------------------------------------------

        public object LoadUser(byte[] blob)
        {
            var formatter = new BinaryFormatter();
            using var ms = new MemoryStream(blob);
            return formatter.Deserialize(ms);
        }

        // ------------------------------------------------------------------
        // Path Traversal
        // ------------------------------------------------------------------

        public string ReadFile(string filename)
        {
            return System.IO.File.ReadAllText("C:\\data\\" + filename);
        }

        // ------------------------------------------------------------------
        // Reflected XSS
        // ------------------------------------------------------------------

        [HttpGet("/hello")]
        public ContentResult Hello(string name)
        {
            return Content("<h1>Hello " + name + "</h1>", "text/html");
        }

        // ------------------------------------------------------------------
        // Weak Cryptography
        // ------------------------------------------------------------------

        public string HashPassword(string password)
        {
            using var md5 = MD5.Create();
            var bytes = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }

        // ------------------------------------------------------------------
        // Improper Error Handling / Information Disclosure
        // ------------------------------------------------------------------

        public IActionResult Divide(int x, int y)
        {
            try
            {
                return Ok(x / y);
            }
            catch (Exception ex)
            {
                return Content(ex.ToString());
            }
        }

        // ------------------------------------------------------------------
        // OS Command via Shell
        // ------------------------------------------------------------------

        public void RunCommand(string cmd)
        {
            Process.Start("cmd.exe", "/c " + cmd);
        }

        // ------------------------------------------------------------------
        // Excessive Complexity
        // ------------------------------------------------------------------

        public string OverlyComplex(bool a, bool b, bool c, bool d)
        {
            if (a)
            {
                if (b)
                {
                    if (c)
                    {
                        if (d)
                        {
                            if (a && b && c && d)
                            {
                                return "too complex";
                            }
                        }
                    }
                }
            }
            return "ok";
        }

        // ------------------------------------------------------------------
        // Insecure File Permissions
        // ------------------------------------------------------------------

        public void WriteSecret()
        {
            var path = "C:\\temp\\secret.txt";
            File.WriteAllText(path, ApiKey);

            // World-writable ACL (conceptual example)
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }
}
