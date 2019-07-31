﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Text;

namespace Amdocs.Ginger.CoreNET
{
    public interface IDatabase
    {
        Boolean OpenConnection(Dictionary<string, string> parameters);
        void CloseConnection();
        List<string> GetTablesList(string Name= null);// Keyspace - cassandra ??
        List<string> GetTablesColumns(string table);
        string RunUpdateCommand(string updateCmd, bool commit = true);
        string GetSingleValue(string Table, string Column, string Where);
        DataTable DBQuery(string Query); //  int? timeout = null : TODO // Return Datatable 
        int GetRecordCount(string Query);

        //string GetConnectionString();
        //bool MakeSureConnectionIsOpen();
        //string GetMissingDLLErrorDescription();
    }
}