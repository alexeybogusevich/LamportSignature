using Lamport;
using System.Text;

string password = "userPassword";
string serverName = "exampleServer";
int N = 1000;

var serverAuth = new LamportAuth(N, password, serverName);

for (int i = 1; i <= N; i++)
{
    var clientHash = LamportAuth.ComputeHashChain(Encoding.UTF8.GetBytes(password + serverName), N - i);
    var isAuthenticated = serverAuth.Authenticate(clientHash);

    Console.WriteLine($"Authentication attempt {i}: {(isAuthenticated ? "Success" : "Failure")}");
}