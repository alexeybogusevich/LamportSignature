using Lamport;
using System.Security.Cryptography;

var lamport = new LamportSignature();

var message = System.Text.Encoding.UTF8.GetBytes("Hello, Lamport!");
var messageHash = SHA256.HashData(message);

var signature = lamport.Sign(messageHash);

bool isValid = LamportSignature.Verify(lamport.PublicKey0, lamport.PublicKey1, messageHash, signature);

Console.WriteLine("Signature valid: " + isValid);