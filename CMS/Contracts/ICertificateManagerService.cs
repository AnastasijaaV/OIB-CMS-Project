using System.ServiceModel;

namespace Contracts
{
    [ServiceContract]
    public interface ICertificateManagerService
    {
        [OperationContract]
        void CreateCertificate(string subjectName, bool includePrivateKey);

        [OperationContract]
        void RevokeCertificate(string serialNumber);

        [OperationContract]
        void ReplicateData();

        [OperationContract]
        void NotifyClientsOfRevocation(string serialNumber);

        [OperationContract]
        bool RequestCertificate(string windowsUsername);
    }
}