//* XML Parser *//
/*  Developed By: Azqa Nadeem - Intern @ DSlab
 * Date : 26th June 2014 10:52 am */

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
        public DateTime date_created;
    }

    class Program
    {

        static void Main(string[] args)
        {

 
            List<int> product_id = new List<int>();
            int entry_id = 0;
            string connStr;
            //string args = "C:\\Users\\Azqa\\Documents\\VisualStudio2012\\Projects\\xmlparser1\\xmlparser\\nvdcve-2.0-2014.xml"; //path to your xml file

            if (args.Length == 0)
            {
                Console.WriteLine("No input file specified");
                Console.ReadLine();
                return;
            }

            FileStream fs;
            byte[] data;
            try
            {
                 fs = new FileStream(args[0], FileMode.Open, FileAccess.Read); //read the file
                 data = new byte[fs.Length];
                fs.Read(data, 0, (int)fs.Length);
                fs.Close();
            }
            catch (DirectoryNotFoundException e)
            {
                Console.WriteLine("XML File Not found. Details:\n" + e.Message);
                Console.ReadLine();
                return;
            }


            HashSet<products> productvendor = new HashSet<products>(); //list of products and vendors for each entry
            string strData = Encoding.UTF8.GetString(data);

            // Read a particular key from the config file            

            if ((ConfigurationManager.AppSettings.Get("server").Length <= 0) || (ConfigurationManager.AppSettings.Get("user").Length <= 0) || (ConfigurationManager.AppSettings.Get("database").Length <= 0))
            {
                Console.WriteLine("App Config not found...");
                Console.ReadLine();
                return;
            }
            else if (args[1].Length<=0) //HERE
            {
                Console.WriteLine("Password not specified..");
                Console.ReadLine();
                return;
            }
            connStr = "server=" + ConfigurationManager.AppSettings.Get("server") +";user=" + ConfigurationManager.AppSettings.Get("user") +";database=" + ConfigurationManager.AppSettings.Get("database") +";port=" + ConfigurationManager.AppSettings.Get("port") +";password=" + args[1] +";"; //connection string
            MySqlConnection conn = new MySqlConnection(connStr);

            try
            {
                Console.WriteLine("Connecting to MySQL...");
               conn.Open();
               Console.WriteLine("Connection Successful. Now attempting to parse and save data in database...");
                string sql; //query string
                NanoXMLDocument xml = new NanoXMLDocument(strData);

                foreach (var entry in xml.RootNode.SubNodes) //nvd/entry
                {
                    product_id.Clear();
                    cve_entries entries = new cve_entries(); //new object for very entry
                    entries.entry = entry.GetAttribute("id").Value; //entry id= "bla-bla"
                    //Console.WriteLine("{0} = {1} ", item.Name, entries.entry); 
                    foreach (var entry_nodes in entry.SubNodes)//nvd/entry/...
                    {

                        if (entry_nodes.Name.Equals("vuln:vulnerable-software-list"))
                        {
                            foreach (var product in entry_nodes.SubNodes)//nvd/entry/software-list/product
                            {

                                //Console.WriteLine("name= {0} ", i2.Value);
                                string[] vendors = product.Value.Split(':');
                                products tempproduct = new products();
                                tempproduct.vendor = vendors[2]; //vendor name
                                tempproduct.product = vendors[3]; //product name
                                bool flag = false;
                                foreach (var productrow in productvendor) //checking duplicates for products
                                {
                                    if (productrow.product == tempproduct.product && productrow.vendor == tempproduct.vendor)
                                        flag = true;

                                }
                                if (!flag) //if instance not found, then try storing in database
                                {
                                    sql = "INSERT INTO products(vendor, product) VALUES (@vendor_val,@product_val);"; //sql query
                                    MySqlCommand insertproduct = new MySqlCommand(sql, conn);
                                    insertproduct.Parameters.AddWithValue("@vendor_val", tempproduct.vendor);
                                    insertproduct.Parameters.AddWithValue("@product_val", tempproduct.product);
                                    try
                                    {
                                        insertproduct.ExecuteScalar();
                                        
                                    }
                                    catch (MySqlException e)
                                    {
                                        Console.WriteLine("Error inserting row in Products Table: \n{0} - ", e.Message);
                                        Console.ReadLine();
                                        return;

                                    }
                                    productvendor.Add(tempproduct); // check for duplicates
                                    sql = "SELECT product_id FROM products WHERE vendor = @vendor_val AND product = @product_val;";

                                    MySqlCommand cmd = new MySqlCommand(sql,conn);
                                    cmd.Parameters.AddWithValue("@vendor_val", tempproduct.vendor);
                                    cmd.Parameters.AddWithValue("@product_val", tempproduct.product);
                                    int prod_id = Convert.ToInt32(cmd.ExecuteScalar());
                                    if (!product_id.Contains(prod_id))
                                        product_id.Add(prod_id);
                                   
                                }
                                else //if instance is found,
                                {
                                   // sql = "SELECT product_id from products WHERE vendor='" + temp.vendor + "' and product= '" + temp.product + "' ;";
                                    sql = "SELECT product_id FROM products WHERE vendor = @vendor_val AND product = @product_val;";
                                    
                                    MySqlCommand cmd = new MySqlCommand(sql,conn);
                                    cmd.Parameters.AddWithValue("@vendor_val", tempproduct.vendor);
                                    cmd.Parameters.AddWithValue("@product_val", tempproduct.product);
                                    int prod_id = Convert.ToInt32(cmd.ExecuteScalar());
                                    if (!product_id.Contains(prod_id))
                                                product_id.Add(prod_id);
                                  

                                }

                            }
                        }
                        if (entry_nodes.Name.Equals("vuln:summary")) 
                        {
                            entries.summary = entry_nodes.Value; //summary
                            //Console.WriteLine("Summary= {0}", entries.summary); //save in db
                        }
                        if (entry_nodes.Name.Equals("vuln:cwe"))
                        {
                            entries.cwe=entry_nodes.GetAttribute("id").Value; //cwe id
                            //Console.WriteLine("cwe= {0}", entries.cwe);
                        }
                        if (entry_nodes.Name.Equals("vuln:cvss")) //nvd/entry/cvss/...
                        {
                            foreach (var cvss_nodes in entry_nodes.SubNodes)
                            {
                                if (cvss_nodes.Name.Equals("cvss:base_metrics"))//nvd/entry/cvss/base_metrics
                                    foreach (var basemetrics_nodes in cvss_nodes.SubNodes) //nvd/entry/cvss/base_metrics/...
                                    {
                                        string[] key = basemetrics_nodes.Name.Split(':');
                                        if (key[1] == "score")
                                            entries.score = basemetrics_nodes.Value;
                                        else if (key[1] == "access-vector")
                                            entries.access_vector = basemetrics_nodes.Value;
                                        else if (key[1] == "access-complexity")
                                            entries.access_complexity = basemetrics_nodes.Value;
                                        else if (key[1] == "authentication")
                                            entries.authentication = basemetrics_nodes.Value;
                                        else if (key[1] == "confidentiality-impact")
                                            entries.confidentiality_impact = basemetrics_nodes.Value;
                                        else if (key[1] == "integrity-impact")
                                            entries.integrity_impact = basemetrics_nodes.Value;
                                        else if (key[1] == "availability-impact")
                                            entries.availablility_impact = basemetrics_nodes.Value;
                                        else if (key[1] == "generated-on-datetime")
                                            entries.date_created = Convert.ToDateTime(basemetrics_nodes.Value); //WRONG VAL
                                        //Console.WriteLine("{0} = {1}", key[1], i5.Value); 
                                    }
                            }
                        }


                    }
                    //Console.WriteLine("{0} - {1} - {2} - {3} -{4} -{5} -{6} -{7} -{8} -{9} ",
                    //    entries.entry, entries.access_complexity, entries.access_vector, entries.authentication,
                    //    entries.availablility_impact, entries.confidentiality_impact, entries.cwe, entries.integrity_impact,
                    //    entries.score, entries.summary);
                    sql = "INSERT INTO cve_entries(entry, cwe, summary, score, access_complexity,"+
                    "access_vector, authentication, availability_impact, confidentiality_impact,"+
                    "integrity_impact, date_created) VALUES (@entry,@cwe,@summary,@score,@ac,@av,@authentication,@ai,@ci,@ii,@date);"; //store all info regarding one entry to database

                    MySqlCommand insertentry = new MySqlCommand(sql, conn);
                    insertentry.Parameters.AddWithValue("@entry",entries.entry );
                    insertentry.Parameters.AddWithValue("@cwe", entries.cwe);
                    insertentry.Parameters.AddWithValue("@summary", entries.summary);
                    insertentry.Parameters.AddWithValue("@score", entries.score);
                    insertentry.Parameters.AddWithValue("@ac", entries.access_complexity);
                    insertentry.Parameters.AddWithValue("@av", entries.access_vector);
                    insertentry.Parameters.AddWithValue("@authentication", entries.authentication);
                    insertentry.Parameters.AddWithValue("@ai", entries.availablility_impact);
                    insertentry.Parameters.AddWithValue("@ci", entries.confidentiality_impact);
                    insertentry.Parameters.AddWithValue("@ii", entries.integrity_impact);
                    insertentry.Parameters.AddWithValue("@date", entries.date_created);
                   

                    try
                    {
                        insertentry.ExecuteScalar();

                    }
                    catch (MySqlException e)
                    {
                        Console.WriteLine("Error inserting row in cve_entries Table: \n{0}", e.Message);
                        Console.ReadLine();
                        return;

                    }

                    sql = "SELECT entry_id FROM cve_entries WHERE entry = @entry_val ;";

                    MySqlCommand cmd1 = new MySqlCommand(sql, conn);
                    cmd1.Parameters.AddWithValue("@entry_val", entries.entry);
                    entry_id = Convert.ToInt32(cmd1.ExecuteScalar());

               
                    foreach (var prod in product_id)
                    {
                        sql = "INSERT INTO product_entries (product_id, entry_id) VALUES (@prod,@entry);";
                        MySqlCommand insertprodentry = new MySqlCommand(sql, conn);
                        insertprodentry.Parameters.AddWithValue("@entry", entry_id);
                        insertprodentry.Parameters.AddWithValue("@prod", prod);


                        try
                        {
                            insertprodentry.ExecuteScalar();
                            //execute query
                        }
                        catch (MySqlException e)
                        {
                            Console.WriteLine("Error inserting row in product_entries Table: \n{0} ", e.Message);
                            Console.ReadLine();
                            return;
                        }
                    }
                }
            }
            catch (XMLParsingException e)
            {
                Console.WriteLine("XML Parsing error: {0}", e.Message);
                Console.ReadLine();

                return;
            }
            Console.WriteLine("Task Completed!!");
            Console.ReadLine();
        }
       
    }


}
