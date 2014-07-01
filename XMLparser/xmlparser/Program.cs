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

    namespace XmlParser
    {

        class Products //structure to store vendors and products info
        {
            public string vendor; 
            public string product;

            public bool Save(MySqlConnection conn)
            {
                string sql = "INSERT INTO products(vendor, product) VALUES (@vendor_val,@product_val);"; //sql query
                MySqlCommand insert_Product = new MySqlCommand(sql, conn);
                insert_Product.Parameters.AddWithValue("@vendor_val", vendor);
                insert_Product.Parameters.AddWithValue("@product_val", product);
                try
                {
                    insert_Product.ExecuteScalar();                           
                }
                catch (MySqlException e)
                {
                    Console.WriteLine("Error inserting row in Products Table: \n{0} - ", e.Message);    
                    return false;

                }
                return true;
            }
            public int Get_Id(MySqlConnection conn)
            {
                string sql = "SELECT product_id FROM products WHERE vendor = @vendor_val AND product = @product_val;";
                MySqlCommand cmd = new MySqlCommand(sql,conn);
                cmd.Parameters.AddWithValue("@vendor_val",vendor);
                cmd.Parameters.AddWithValue("@product_val", product);
                return Convert.ToInt32(cmd.ExecuteScalar());
            }
        }

        class Product_Entry //structure to link vulnerability to product
        {
            public HashSet<int> product_Ids = new HashSet<int>();
            public int entry_Id;

            public bool Save(MySqlConnection conn)
            {
            foreach (var product in product_Ids)
            {
                string sql = "INSERT INTO product_entries (product_id, entry_id) VALUES (@prod,@entry);";
                MySqlCommand insert_Prod_Entry = new MySqlCommand(sql, conn);

                insert_Prod_Entry.Parameters.AddWithValue("@entry", entry_Id);
                insert_Prod_Entry.Parameters.AddWithValue("@prod", product); //fix

                try
                {
                    insert_Prod_Entry.ExecuteScalar();
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

        class Cve_Entries //structure to store info about vulnerabilities
        {

            public string entry = null;
            public string summary = null;
            public string score = null;
            public string access_Vector = null;
            public string access_Complexity = null;
            public string authentication = null;
            public string confidentiality_Impact = null;
            public string integrity_Impact = null;
            public string availablility_Impact = null;
            public string cwe = null;
            public DateTime date_Created;
            public DateTime date_Published;
            public DateTime last_Modified;

            public bool Save(MySqlConnection conn)
            {
                string sql = "INSERT INTO cve_entries(entry, cwe, summary, score, access_complexity,"+
                "access_vector, authentication, availability_impact, confidentiality_impact,"+
                "integrity_impact, date_created, published_date, last_modified) VALUES (@entry,@cwe,@summary,"+
                "@score,@ac,@av,@authentication,@ai,@ci,@ii,@date_created,@date_pub,@last_mod);"; 
                //store all info regarding one entry to database

                MySqlCommand insert_Entry = new MySqlCommand(sql, conn);
                insert_Entry.Parameters.AddWithValue("@entry",entry );
                insert_Entry.Parameters.AddWithValue("@cwe", cwe);
                insert_Entry.Parameters.AddWithValue("@summary",  summary);
                insert_Entry.Parameters.AddWithValue("@score",  score);
                insert_Entry.Parameters.AddWithValue("@ac",  access_Complexity);
                insert_Entry.Parameters.AddWithValue("@av",  access_Vector);
                insert_Entry.Parameters.AddWithValue("@authentication",  authentication);
                insert_Entry.Parameters.AddWithValue("@ai",  availablility_Impact);
                insert_Entry.Parameters.AddWithValue("@ci",  confidentiality_Impact);
                insert_Entry.Parameters.AddWithValue("@ii",  integrity_Impact);
                insert_Entry.Parameters.AddWithValue("@date_created",  date_Created);
                insert_Entry.Parameters.AddWithValue("@date_pub",  date_Published);
                insert_Entry.Parameters.AddWithValue("@last_mod",  last_Modified);

                try
                {
                    insert_Entry.ExecuteScalar();
                }
                catch (MySqlException e)
                {
                    Console.WriteLine("Error inserting row in cve_entries Table: \n{0}", e.Message);             
                    return false;

                }
                return true;

            }
            public int Get_Id(MySqlConnection conn)
            {
                string sql = "SELECT entry_id FROM cve_entries WHERE entry = @entry_val ;";
                MySqlCommand cmd1 = new MySqlCommand(sql, conn);
                cmd1.Parameters.AddWithValue("@entry_val", entry);
                return Convert.ToInt32(cmd1.ExecuteScalar());
            }
        }

        class Program
        {
            public static byte[] Load_XML(string args)
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
            public static bool Read_AppConfig()
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
            {
                string conn_Str;
                if (args.Length < 2 )
                {
                    Console.WriteLine("usage: < Path\\to\\XML\\File.xml Password-of-database >");
                    return -1;
                }

                HashSet<Products> product_Vendor = new HashSet<Products>(); //list of products and vendors for each entry
                byte[] data = Load_XML(args[0]);
                string str_Data;
                if (data != null)
                    str_Data = Encoding.UTF8.GetString(data);
                else
                    return -1;

                if (!Read_AppConfig())
                    return -1;

                else if (args[1] == null)
                {
                    Console.WriteLine("Password not specified..");
                    return -1;
                }

           

            try
            {
               conn.Open();
               Console.WriteLine("Connection Successful. Now attempting to parse and save data in database...");
                NanoXMLDocument xml = new NanoXMLDocument(str_data);
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
                    Console.WriteLine("Connecting to MySQL...");
                    conn.Open();
                    Console.WriteLine("Connection Successful. Now attempting to parse and save data in database...");
                    NanoXMLDocument xml = new NanoXMLDocument(str_Data);

                    foreach (var entry in xml.RootNode.SubNodes) //nvd/entry
                    {
                        Product_Entry p_e = new Product_Entry(); 
                        Cve_Entries entries = new Cve_Entries(); //new object for very entry
                        entries.entry = entry.GetAttribute("id").Value; //entry id= "bla-bla"
                        foreach (var entry_nodes in entry.SubNodes)//nvd/entry/...
                        {
                            if (entry_nodes.Name.Equals("vuln:published-datetime"))
                            {
                                entries.date_Published = Convert.ToDateTime(entry_nodes.Value);
                            }
                            else if (entry_nodes.Name.Equals("vuln:last-modified-datetime"))
                            {
                                entries.last_Modified = Convert.ToDateTime(entry_nodes.Value);
                            }
                            else if (entry_nodes.Name.Equals("vuln:vulnerable-software-list"))
                            {
                                foreach (var product in entry_nodes.SubNodes)//nvd/entry/software-list/product
                                {
                                    string[] vendors = product.Value.Split(':');
                                    Products temp_Product = new Products();
                                    temp_Product.vendor = vendors[2]; //vendor name
                                    temp_Product.product = vendors[3]; //product name
                                    bool flag = false;
                                    foreach (var product_Row in product_Vendor) //checking duplicates for products
                                    {
                                        if (product_Row.product == temp_Product.product && product_Row.vendor == temp_Product.vendor)
                                        flag = true;
                                    }
                                    if (!flag) //if instance not found, then try storing in database
                                    {
                                        if(!temp_Product.Save(conn)) //store product
                                            return -1;
                                        product_Vendor.Add(temp_Product); // to check for duplicates\
                                    }
                                        p_e.product_Ids.Add(temp_Product.Get_Id(conn)); //list of products' ids
                                }
                            }
                            else if (entry_nodes.Name.Equals("vuln:summary")) 
                            {
                                entries.summary = entry_nodes.Value; //summary
                            }
                            else if (entry_nodes.Name.Equals("vuln:cwe"))
                            {
                                entries.cwe=entry_nodes.GetAttribute("id").Value; //cwe id
                            }
                            else if (entry_nodes.Name.Equals("vuln:cvss")) //nvd/entry/cvss/...
                            {
                                foreach (var cvss_Nodes in entry_nodes.SubNodes)
                                {
                                    if (cvss_Nodes.Name.Equals("cvss:base_metrics"))//nvd/entry/cvss/base_metrics
                                        foreach (var basemetrics_Nodes in cvss_Nodes.SubNodes) //nvd/entry/cvss/base_metrics/...
                                        {
                                            string[] key = basemetrics_Nodes.Name.Split(':');
                                            if (key[1] == "score")
                                                entries.score = basemetrics_Nodes.Value;
                                            else if (key[1] == "access-vector")
                                                entries.access_Vector = basemetrics_Nodes.Value;
                                            else if (key[1] == "access-complexity")
                                                entries.access_Complexity = basemetrics_Nodes.Value;
                                            else if (key[1] == "authentication")
                                                entries.authentication = basemetrics_Nodes.Value;
                                            else if (key[1] == "confidentiality-impact")
                                                entries.confidentiality_Impact = basemetrics_Nodes.Value;
                                            else if (key[1] == "integrity-impact")
                                                entries.integrity_Impact = basemetrics_Nodes.Value;
                                            else if (key[1] == "availability-impact")
                                                entries.availablility_Impact = basemetrics_Nodes.Value;
                                            else if (key[1] == "generated-on-datetime")
                                                entries.date_Created = Convert.ToDateTime(basemetrics_Nodes.Value); 
                                        }
                                }
                            }
                        }
                        if(!entries.Save(conn))  //store entry 
                            return -1;

                        p_e.entry_Id = entries.Get_Id(conn);

                        if (!p_e.Save(conn)) //store link b/w entry and product
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

