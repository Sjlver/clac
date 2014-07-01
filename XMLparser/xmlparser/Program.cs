//* XML Parser *//
/*  Developed By: Azqa Nadeem - Intern @ DSlab
 * Date : 30th June 2014 2:44 pm */

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

        public bool store_product(MySqlConnection conn)
        {
            string sql = "INSERT INTO products(vendor, product) VALUES (@vendor_val,@product_val);"; //sql query
            MySqlCommand insert_product = new MySqlCommand(sql, conn);
            insert_product.Parameters.AddWithValue("@vendor_val", vendor);
            insert_product.Parameters.AddWithValue("@product_val", product);
            try
            {
                insert_product.ExecuteScalar();
                                        
            }
            catch (MySqlException e)
            {
                Console.WriteLine("Error inserting row in Products Table: \n{0} - ", e.Message);
                 
                return false;

            }
            return true;

        }

        public int load_product(MySqlConnection conn)
        {
            string sql = "SELECT product_id FROM products WHERE vendor = @vendor_val AND product = @product_val;";
            MySqlCommand cmd = new MySqlCommand(sql,conn);
            cmd.Parameters.AddWithValue("@vendor_val",vendor);
            cmd.Parameters.AddWithValue("@product_val", product);
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
    }
    class product_entry //structure to link vulnerability to product
    {
        public HashSet<int> product_ids = new HashSet<int>();
        public int entry_id;

        public bool store_product_entry(MySqlConnection conn)
        {
            foreach (var product in product_ids)
            {
                string sql = "INSERT INTO product_entries (product_id, entry_id) VALUES (@prod,@entry);";
                MySqlCommand insert_prod_entry = new MySqlCommand(sql, conn);

                insert_prod_entry.Parameters.AddWithValue("@entry", entry_id);
                insert_prod_entry.Parameters.AddWithValue("@prod", product); //fix

                try
                {
                    insert_prod_entry.ExecuteScalar();
                    //execute query
                }
                catch (MySqlException e)
                {
                    Console.WriteLine("Error inserting row in product_entries Table: \n{0} ", e.Message);
                     
                    return false;
                }
            }
            return true;
        }

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
        public DateTime date_published;
        public DateTime last_modified;

        public bool store_entry(MySqlConnection conn)
        {
                    string sql = "INSERT INTO cve_entries(entry, cwe, summary, score, access_complexity,"+
                    "access_vector, authentication, availability_impact, confidentiality_impact,"+
                    "integrity_impact, date_created, published_date, last_modified) VALUES (@entry,@cwe,@summary,"+
                    "@score,@ac,@av,@authentication,@ai,@ci,@ii,@date_created,@date_pub,@last_mod);"; 
                    //store all info regarding one entry to database

                    MySqlCommand insert_entry = new MySqlCommand(sql, conn);
                    insert_entry.Parameters.AddWithValue("@entry",entry );
                    insert_entry.Parameters.AddWithValue("@cwe", cwe);
                    insert_entry.Parameters.AddWithValue("@summary",  summary);
                    insert_entry.Parameters.AddWithValue("@score",  score);
                    insert_entry.Parameters.AddWithValue("@ac",  access_complexity);
                    insert_entry.Parameters.AddWithValue("@av",  access_vector);
                    insert_entry.Parameters.AddWithValue("@authentication",  authentication);
                    insert_entry.Parameters.AddWithValue("@ai",  availablility_impact);
                    insert_entry.Parameters.AddWithValue("@ci",  confidentiality_impact);
                    insert_entry.Parameters.AddWithValue("@ii",  integrity_impact);
                    insert_entry.Parameters.AddWithValue("@date_created",  date_created);
                    insert_entry.Parameters.AddWithValue("@date_pub",  date_published);
                    insert_entry.Parameters.AddWithValue("@last_mod",  last_modified);

                    try
                    {
                        insert_entry.ExecuteScalar();

                    }
                    catch (MySqlException e)
                    {
                        Console.WriteLine("Error inserting row in cve_entries Table: \n{0}", e.Message);
                         
                        return false;

                    }
            return true;

        }

        public int load_entry(MySqlConnection conn)
        {
            string sql = "SELECT entry_id FROM cve_entries WHERE entry = @entry_val ;";
            MySqlCommand cmd1 = new MySqlCommand(sql, conn);
            cmd1.Parameters.AddWithValue("@entry_val", entry);
            return Convert.ToInt32(cmd1.ExecuteScalar());
        }
    }

    class Program
    {
        public static byte[] load_xml(string args)
        {
        FileStream fs;
        byte[] data;
        try
        {
            fs = new FileStream(args, FileMode.Open, FileAccess.Read); //read the file
            data = new byte[fs.Length];
            fs.Read(data, 0, (int)fs.Length);
            fs.Close();
        }
        catch (DirectoryNotFoundException e)
        {
            Console.WriteLine("XML File Not found. Details:\n" + e.Message);
             
            return null;
        }
        return data;
        }
        public static bool read_AppConfig()
        {
             if ((ConfigurationManager.AppSettings.Get("server").Length <= 0) || 
                (ConfigurationManager.AppSettings.Get("user").Length <= 0) || 
                (ConfigurationManager.AppSettings.Get("database").Length <= 0))
            {
                Console.WriteLine("App Config not found...");
                 
                return false;
            }
             return true;
        }

        static int Main(string[] args)
        {//

            
            string conn_str;
            //string args = "C:\\Users\\Azqa\\Documents\\VisualStudio2012\\Projects\\xmlparser1\\xmlparser\\nvdcve-2.0-2014.xml"; //path to your xml file

            if (args.Length < 2 )
            {
                Console.WriteLine("usage: < Path\\to\\XML\\File.xml Password-of-database >");
                 
                return -1;
            }

           
            HashSet<products> product_vendor = new HashSet<products>(); //list of products and vendors for each entry
            byte[] data = load_xml(args[0]);
            string str_data;
            if (data != null)
                str_data = Encoding.UTF8.GetString(data);
            else
                return -1;

            if (!read_AppConfig())
                return -1;

            else if (args[1] == null)
            {
                Console.WriteLine("Password not specified..");
                 
                return -1;
            }

            Console.WriteLine("Connecting to MySQL server at " +
                    ConfigurationManager.AppSettings.Get("server") +
                    ":" + ConfigurationManager.AppSettings.Get("port") + "...");
            Console.WriteLine("Using " +
                    ConfigurationManager.AppSettings.Get("user") + "@" +
                    ConfigurationManager.AppSettings.Get("database") + ".");
            conn_str = "server=" + ConfigurationManager.AppSettings.Get("server") +";user=" +
                ConfigurationManager.AppSettings.Get("user") +";database=" +
                ConfigurationManager.AppSettings.Get("database") +";port=" +
                ConfigurationManager.AppSettings.Get("port") +";password=" + args[1] +";"; //connection string
            MySqlConnection conn = new MySqlConnection(conn_str);

            try
            {
               conn.Open();
               Console.WriteLine("Connection Successful. Now attempting to parse and save data in database...");
                NanoXMLDocument xml = new NanoXMLDocument(str_data);

                foreach (var entry in xml.RootNode.SubNodes) //nvd/entry
                {
                    product_entry p_e = new product_entry(); 
                    cve_entries entries = new cve_entries(); //new object for very entry
                    entries.entry = entry.GetAttribute("id").Value; //entry id= "bla-bla"

                    foreach (var entry_nodes in entry.SubNodes)//nvd/entry/...
                    {
                        if (entry_nodes.Name.Equals("vuln:published-datetime"))
                        {
                            entries.date_published = Convert.ToDateTime(entry_nodes.Value);
                        }
                        else if (entry_nodes.Name.Equals("vuln:last-modified-datetime"))
                        {
                            entries.last_modified = Convert.ToDateTime(entry_nodes.Value);
                        }
                        else if (entry_nodes.Name.Equals("vuln:vulnerable-software-list"))
                        {
                            foreach (var product in entry_nodes.SubNodes)//nvd/entry/software-list/product
                            {

                                //Console.WriteLine("name= {0} ", i2.Value);
                                string[] vendors = product.Value.Split(':');
                                products temp_product = new products();
                                temp_product.vendor = vendors[2]; //vendor name
                                temp_product.product = vendors[3]; //product name
                                bool flag = false;
                                foreach (var product_row in product_vendor) //checking duplicates for products
                                {
                                    if (product_row.product == temp_product.product && product_row.vendor == temp_product.vendor)
                                        flag = true;

                                }
                                if (!flag) //if instance not found, then try storing in database
                                {
                                    if(!temp_product.store_product(conn)) //store product
                                        return -1;
                                    product_vendor.Add(temp_product); // to check for duplicates
                        
                                }
                                p_e.product_ids.Add(temp_product.load_product(conn)); //list of products' ids
                            }
                        }
                        else if (entry_nodes.Name.Equals("vuln:summary")) 
                        {
                            entries.summary = entry_nodes.Value; //summary
                            //Console.WriteLine("Summary= {0}", entries.summary); //save in db
                        }
                        else if (entry_nodes.Name.Equals("vuln:cwe"))
                        {
                            entries.cwe=entry_nodes.GetAttribute("id").Value; //cwe id
                            //Console.WriteLine("cwe= {0}", entries.cwe);
                        }
                        else if (entry_nodes.Name.Equals("vuln:cvss")) //nvd/entry/cvss/...
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
                                            entries.date_created = Convert.ToDateTime(basemetrics_nodes.Value); 
                                        //Console.WriteLine("{0} = {1}", key[1], i5.Value); 
                                    }
                            }
                        }


                    }
                    
                    if(!entries.store_entry(conn))  //store entry 
                        return -1;

                    p_e.entry_id = entries.load_entry(conn);

                     if (!p_e.store_product_entry(conn)) //store link b/w entry and product
                        return -1;
                    
                }
            }
            catch (XMLParsingException e)
            {
                Console.WriteLine("XML Parsing error: {0}", e.Message);
                 

                return -1;
            }
            Console.WriteLine("Task Completed!!");
             
            return 0;
        }
       
    }


}

