//* XML Parser *//
/*  Developed By: Azqa Nadeem - Intern @ DSlab
 * Date : 26th Junem 2014 10:52 am */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using MySql.Data;
using System.Text;
using System.Xml;
using TObject.Shared;
using MySql.Data.MySqlClient;
using System.Configuration;
using System.Collections.Specialized;

namespace xmlparser
{
    class products //structure to store vendors and products info
    {
        public string vendor; 
        public string product;
    }
    class cve_entries //structure to store info about vulnerabilities
    {

        public string entry = null;
        public string summary = null;
        public string score = null;
        public string access_vector = null;
        public string access_complexity = null;
        public string authentication = null;
        public string confidentiality_impact = null;
        public string integrity_impact = null;
        public string availablility_impact = null;
        public string cwe = null;
    }

    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("No input file specified");
                Console.ReadLine();
                return;
            }

            FileStream fs = new FileStream(args[0], FileMode.Open, FileAccess.Read); //read the file
            byte[] data = new byte[fs.Length];
            fs.Read(data, 0, (int)fs.Length);
            fs.Close();

            HashSet<products> vendor = new HashSet<products>(); //list of products and vendors for each entry
            string strData = Encoding.UTF8.GetString(data);

            Console.WriteLine("Connecting to database \"" + ConfigurationManager.AppSettings.Get("server") + "\"...");

            string connStr = "server=" + ConfigurationManager.AppSettings.Get("server") +";user=" + ConfigurationManager.AppSettings.Get("user") +";database=" + ConfigurationManager.AppSettings.Get("database") +";port=" + ConfigurationManager.AppSettings.Get("port") +";password=" + ConfigurationManager.AppSettings.Get("password") +";"; //connection string
            MySqlConnection conn = new MySqlConnection(connStr); 
            int product_id=0;
            int entry_id = 0;
            try
            {
                Console.WriteLine("Connecting to MySQL...");
               conn.Open();

                string sql; //query string
                NanoXMLDocument xml = new NanoXMLDocument(strData);

                foreach (var item in xml.RootNode.SubNodes) //nvd/entry
                {
                    cve_entries entries = new cve_entries(); //new object for very entry
                    entries.entry = item.GetAttribute("id").Value; //entry id= "bla-bla"
                    //Console.WriteLine("{0} = {1} ", item.Name, entries.entry); 
                    foreach (var i in item.SubNodes)//nvd/entry/...
                    {
                        
                        if (i.Name.Equals("vuln:vulnerable-software-list"))
                            foreach (var i2 in i.SubNodes)//nvd/entry/software-list/product
                            {

                                //Console.WriteLine("name= {0} ", i2.Value);
                                string[] vendors = i2.Value.Split(':'); 
                                products temp = new products();
                                temp.vendor = vendors[2]; //vendor name
                                temp.product = vendors[3]; //product name
                                bool flag = false;
                                foreach (var i3 in vendor) //checking duplicates for products
                                {
                                    if (i3.product == temp.product && i3.vendor == temp.vendor) 
                                        flag = true;

                                }
                                if (!flag) //if instance not found, then try storing in database
                                {
                                    sql = "INSERT INTO products(vendor, product) VALUES ('" + temp.vendor + "','" + temp.product + "');"; //sql query
                                    MySqlScript script = new MySqlScript(conn, sql);
                                    script.Error += new MySqlScriptErrorEventHandler(script_Error);
                                    script.ScriptCompleted += new EventHandler(script_ScriptCompleted);
                                    script.StatementExecuted += new MySqlStatementExecutedEventHandler(script_StatementExecuted);
                                    int count = script.Execute(); //execute query
                                    
                                    sql = "SELECT product_id from products ORDER BY product_id DESC LIMIT 1"; //get the id of newly created row
                                    MySqlCommand cmd = new MySqlCommand(sql, conn);

                                    MySqlDataReader reader = cmd.ExecuteReader();
                                    while (reader.Read())
                                    {
                                        product_id = reader.GetInt16("product_id"); //store in product_id
                                    }
                                    reader.Close();


                                    vendor.Add(temp); //add to list to check for duplications
                                }
                                else //if instance is found,
                                {
                                    sql = "SELECT product_id from products WHERE vendor='"+temp.vendor+"' and product= '"+temp.product+"' ;";
                                    MySqlCommand cmd = new MySqlCommand(sql, conn);

                                    MySqlDataReader reader = cmd.ExecuteReader();
                                    while (reader.Read())
                                    {
                                        product_id = reader.GetInt16("product_id"); //try looking for its id
                                    }
                                    reader.Close();

                                }
                                
                            }
                        if (i.Name.Equals("vuln:summary")) 
                        {
                            entries.summary = i.Value; //summary
                            //Console.WriteLine("Summary= {0}", entries.summary); //save in db
                        }
                        if (i.Name.Equals("vuln:cwe"))
                        {
                            entries.cwe=i.GetAttribute("id").Value; //cwe id
                            //Console.WriteLine("cwe= {0}", entries.cwe);
                        }
                        if (i.Name.Equals("vuln:cvss")) //nvd/entry/cvss/...
                            foreach(var i4 in i.SubNodes)
                                if (i4.Name.Equals("cvss:base_metrics"))//nvd/entry/cvss/base_metrics
                                    foreach (var i5 in i4.SubNodes) //nvd/entry/cvss/base_metrics/...
                                    {
                                        string[] key = i5.Name.Split(':');
                                        if (key[1] == "score")
                                            entries.score = i5.Value; 
                                        else if (key[1]== "access-vector")
                                            entries.access_vector = i5.Value;
                                        else if (key[1] == "access-complexity")
                                            entries.access_complexity = i5.Value;
                                        else if (key[1] == "authentication")
                                            entries.authentication = i5.Value;
                                        else if (key[1] == "confidentiality-impact")
                                            entries.confidentiality_impact = i5.Value;
                                        else if (key[1] == "integrity-impact")
                                            entries.integrity_impact = i5.Value;
                                        else if (key[1] == "availability-impact")
                                            entries.availablility_impact = i5.Value;
                                        //Console.WriteLine("{0} = {1}", key[1], i5.Value); 
                                    }


                    }
                    //Console.WriteLine("{0} - {1} - {2} - {3} -{4} -{5} -{6} -{7} -{8} -{9} ",
                    //    entries.entry, entries.access_complexity, entries.access_vector, entries.authentication,
                    //    entries.availablility_impact, entries.confidentiality_impact, entries.cwe, entries.integrity_impact,
                    //    entries.score, entries.summary);
                    sql = "INSERT INTO cve_entries(entry, cwe, summary, score, access_complexity,"+
                    "access_vector, authentication, availability_impact, confidentiality_impact,"+
                    "integrity_impact) VALUES ('"+entries.entry+"','"+entries.cwe+"','"+entries.summary+"',"+
                    entries.score+",'"+entries.access_complexity+"','"+entries.access_vector+"','"+
                    entries.authentication+"','"+entries.availablility_impact+"','"+
                    entries.confidentiality_impact+"','"+entries.integrity_impact+"');"; //store all info regarding one entry to database

                    MySqlScript script1 = new MySqlScript(conn, sql);
                    script1.Error += new MySqlScriptErrorEventHandler(script_Error);
                    script1.ScriptCompleted += new EventHandler(script_ScriptCompleted);
                    script1.StatementExecuted += new MySqlStatementExecutedEventHandler(script_StatementExecuted);
                    int count1 = script1.Execute(); //execute the query
                    sql = "SELECT entry_id from cve_entries ORDER BY entry_id DESC LIMIT 1";
                    
                    MySqlCommand cmd1 = new MySqlCommand(sql, conn);
                    MySqlDataReader reader1 = cmd1.ExecuteReader();
                    while (reader1.Read())
                    {
                        entry_id = reader1.GetInt16("entry_id"); //read the entry_id of the newly created entry
                    }
                    reader1.Close();
                    
                    sql = "INSERT INTO product_entries (product_id, entry_id) VALUES ('" + product_id + "','" + entry_id + "');";
                    MySqlScript script3 = new MySqlScript(conn, sql);
                    script3.Error += new MySqlScriptErrorEventHandler(script_Error);
                    script3.ScriptCompleted += new EventHandler(script_ScriptCompleted);
                    script3.StatementExecuted += new MySqlStatementExecutedEventHandler(script_StatementExecuted);
                    int count3 = script3.Execute(); //query to store info in bridge entity
                }
            }
            catch (XMLParsingException e)
            {
                Console.WriteLine("XML Parsing error: {0}", e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("General exception: [{0}]{1}", e.GetType().Name, e.Message);
            }
            Console.ReadLine();
        }
        static void script_StatementExecuted(object sender, MySqlScriptEventArgs args)
        {
            Console.WriteLine("script_StatementExecuted");
        }

        static void script_ScriptCompleted(object sender, EventArgs e)
        {
            /// EventArgs e will be EventArgs.Empty for this method 
            Console.WriteLine("script_ScriptCompleted!");
        }

        static void script_Error(Object sender, MySqlScriptErrorEventArgs args)
        {
            Console.WriteLine("script_Error: " + args.Exception.ToString());
        }
    }

}
