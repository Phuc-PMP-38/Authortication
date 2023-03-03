using Authortication.Models;

namespace Authortication.Repository
{
    public interface IEmailService
    {
        void SendEmail(Message message);
        void TestEmail();
    }
}
