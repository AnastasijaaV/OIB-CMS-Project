﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ServiceModel;

namespace Contracts
{
    [ServiceContract]
    public interface IWCFContract
    {
        [OperationContract]
        void TestCommunication(int id);

        [OperationContract]
        void DisconnectNotice();
    }
}
