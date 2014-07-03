//* XML Parser *//
/*  Developed By: Azqa Nadeem - Intern @ DSlab
 *  Date : 30th June 2014 2:44 pm */

using MySql.Data.MySqlClient;
using MySql.Data;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml;
using System;
using TObject.Shared;


namespace XmlParser
{
    // Product is a structure to store vendors and products info.
    class Product
    {

        public string VendorName;
        public string ProductName;

        public bool Save(MySqlConnection conn)
        {
            const int MYSQL_ERROR_DUPLICATE_ENTRY = 1062;
            string sql = "INSERT INTO products(vendor, product) VALUES (@vendorval,@productval);";
            MySqlCommand insertProduct = new MySqlCommand(sql, conn);
            insertProduct.Parameters.AddWithValue("@vendorval", VendorName);
            insertProduct.Parameters.AddWithValue("@productval", ProductName);
            try
            {
                insertProduct.ExecuteScalar();
            }
            catch (MySqlException e)
            {
                if (e.Number != MYSQL_ERROR_DUPLICATE_ENTRY)
                {
                    throw new Exception("Error inserting row in Products Table: \n"+ e.Message);
                    //return false;
                }
            }
            return true;
        }

        public int GetId(MySqlConnection conn)
        {
            string sql = "SELECT product_id FROM products WHERE vendor = @vendorval AND product = @productval;";
            MySqlCommand cmd = new MySqlCommand(sql,conn);
            cmd.Parameters.AddWithValue("@vendorval",VendorName);
            cmd.Parameters.AddWithValue("@productval", ProductName);
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
    }

    // Structure to link a vulnerability to a product
    class ProductEntry
    {
        public HashSet<int> ProductIds = new HashSet<int>();
        public int EntryId;

        public bool Save(MySqlConnection conn)
        {
            const int MYSQL_ERROR_DUPLICATE_ENTRY = 1062;

            foreach (var product in ProductIds)
            {
                string sql = "INSERT INTO product_entries (product_id, entry_id) VALUES (@prod,@entry);";
                MySqlCommand insertProdEntry = new MySqlCommand(sql, conn);

                insertProdEntry.Parameters.AddWithValue("@entry", EntryId);
                insertProdEntry.Parameters.AddWithValue("@prod", product);

                try
                {
                    insertProdEntry.ExecuteScalar();
                }
                catch (MySqlException e)
                {
                    if (e.Number != MYSQL_ERROR_DUPLICATE_ENTRY)
                    {
                        throw new Exception("Error inserting row in product_entries Table: \n "+ e.Message);
                        return false;
                    }
                }
            }
            return true;
        }
    }

    // Stores info about a CVE vulnerability
    class CveEntry
    {
       
        public string Entry = null;
        public string Summary = null;
        public string Score = null;
        public string AccessVector = null;
        public string AccessComplexity = null;
        public string Authentication = null;
        public string ConfidentialityImpact = null;
        public string IntegrityImpact = null;
        public string AvailablilityImpact = null;
        public string Cwe = null;
        public DateTime DateCreated;
        public DateTime DatePublished;
        public DateTime LastModified;

        public bool Save(MySqlConnection conn)
        {
            const int MYSQL_ERROR_DUPLICATE_ENTRY = 1062;

            //store all info regarding one entry to database
            string sql = "INSERT INTO cve_entries(entry, cwe, summary, score, access_complexity,"+
            "access_vector, authentication, availability_impact, confidentiality_impact,"+
            "integrity_impact, date_created, published_date, last_modified) VALUES (@entry,@cwe,@summary,"+
            "@score,@ac,@av,@authentication,@ai,@ci,@ii,@datecreated,@datepub,@lastmod);";

            MySqlCommand insertEntry = new MySqlCommand(sql, conn);
            insertEntry.Parameters.AddWithValue("@entry",Entry );
            insertEntry.Parameters.AddWithValue("@cwe", Cwe);
            insertEntry.Parameters.AddWithValue("@summary",  Summary);
            insertEntry.Parameters.AddWithValue("@score",  Score);
            insertEntry.Parameters.AddWithValue("@ac",  AccessComplexity);
            insertEntry.Parameters.AddWithValue("@av",  AccessVector);
            insertEntry.Parameters.AddWithValue("@authentication",  Authentication);
            insertEntry.Parameters.AddWithValue("@ai",  AvailablilityImpact);
            insertEntry.Parameters.AddWithValue("@ci",  ConfidentialityImpact);
            insertEntry.Parameters.AddWithValue("@ii",  IntegrityImpact);
            insertEntry.Parameters.AddWithValue("@datecreated",  DateCreated);
            insertEntry.Parameters.AddWithValue("@datepub",  DatePublished);
            insertEntry.Parameters.AddWithValue("@lastmod",  LastModified);

            try
            {
                insertEntry.ExecuteScalar();
            }
            catch (MySqlException e)
            {
                if (e.Number != MYSQL_ERROR_DUPLICATE_ENTRY)
                {
                    throw new Exception("Error inserting row in cveentries Table: \n"+ e.Message);
                    //return false;
                }
            }
            return true;
        }

        public int GetId(MySqlConnection conn)
        {
            string sql = "SELECT entry_id FROM cve_entries WHERE entry = @entryval ;";
            MySqlCommand cmd1 = new MySqlCommand(sql, conn);
            cmd1.Parameters.AddWithValue("@entryval", Entry);
            return Convert.ToInt32(cmd1.ExecuteScalar());
        }
    }

    class Program
    {
        public static byte[] LoadXml(string args)
        {
            FileStream fs;
            byte[] data;
            try
            {
                // read the file
                fs = new FileStream(args, FileMode.Open, FileAccess.Read);
                data = new byte[fs.Length];
                fs.Read(data, 0, (int)fs.Length);
                fs.Close();
            }
            catch (DirectoryNotFoundException e)
            {
                throw new Exception("XML File Not found. Details:\n" + e.Message);
                return null;
            }
            return data;
        }

        public static bool ReadAppConfig()
        {
            if ((ConfigurationManager.AppSettings.Get("server").Length <= 0) ||
                (ConfigurationManager.AppSettings.Get("user").Length <= 0) ||
                (ConfigurationManager.AppSettings.Get("database").Length <= 0))
            {
                throw new Exception("App Config not found...");
                return false;
            }
            return true;
        }

        static int Main(string[] args)
        {
            if (args.Length < 2 )
            {
                throw new Exception("usage: Program.exe <Path\\to\\XML\\File.xml> <database password>");
                return -1;
            }

            if (!ReadAppConfig())
                return -1;

            else if (args[1] == null)
            {
                throw new Exception("Password not specified..");
                return -1;
            }

                        
            string strData;
            try
            {
                Console.WriteLine("Connecting to MySQL server at " +
                                  ConfigurationManager.AppSettings.Get("server") +
                                  ":" + ConfigurationManager.AppSettings.Get("port") + "...");
                Console.WriteLine("Using " +
                                  ConfigurationManager.AppSettings.Get("user") + "@" +
                                  ConfigurationManager.AppSettings.Get("database") + ".");
                string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                    ";user=" + ConfigurationManager.AppSettings.Get("user") +
                    ";database=" + ConfigurationManager.AppSettings.Get("database") +
                    ";port=" + ConfigurationManager.AppSettings.Get("port") +
                    ";password=" + args[1] + ";";
                MySqlConnection conn = new MySqlConnection(connectionString);

                conn.Open();
                Console.WriteLine("Connection Successful. Now attempting to parse and save data in database...");
                byte[] data = LoadXml(args[0]);
                if (data != null)
                    strData = Encoding.UTF8.GetString(data);
                else
                    return -1;
                NanoXMLDocument xml = new NanoXMLDocument(strData);

                foreach (var entryNode in xml.RootNode.SubNodes) //nvd/entry
                {
                    ProductEntry productEntry = new ProductEntry();
                    CveEntry cveEntry = new CveEntry(); //new object for very entry
                    cveEntry.Entry = entryNode.GetAttribute("id").Value; //entry id= "bla-bla"
                    foreach (var entrySubNode in entryNode.SubNodes) //nvd/entry/...
                    {
                        if (entrySubNode.Name.Equals("vuln:published-datetime"))
                        {
                            cveEntry.DatePublished = Convert.ToDateTime(entrySubNode.Value);
                        }
                        else if (entrySubNode.Name.Equals("vuln:last-modified-datetime"))
                        {
                            cveEntry.LastModified = Convert.ToDateTime(entrySubNode.Value);
                        }
                        else if (entrySubNode.Name.Equals("vuln:vulnerable-software-list"))
                        {
                            foreach (var productNode in entrySubNode.SubNodes) //nvd/entry/software-list/product
                            {
                                string[] vendors = productNode.Value.Split(':');
                                Product tempProduct = new Product();
                                tempProduct.VendorName = vendors[2]; //vendor name
                                tempProduct.ProductName = vendors[3]; //product name

                                if(!tempProduct.Save(conn)) //store product
                                    return -1;
                                
                                productEntry.ProductIds.Add(tempProduct.GetId(conn)); //list of products' ids
                            }
                        }
                        else if (entrySubNode.Name.Equals("vuln:summary"))
                        {
                            cveEntry.Summary = entrySubNode.Value; //summary
                        }
                        else if (entrySubNode.Name.Equals("vuln:cwe"))
                        {
                            cveEntry.Cwe = entrySubNode.GetAttribute("id").Value; //cwe id
                        }
                        else if (entrySubNode.Name.Equals("vuln:cvss")) //nvd/entry/cvss/...
                        {
                            foreach (var cvssNodes in entrySubNode.SubNodes)
                            {
                                if (cvssNodes.Name.Equals("cvss:base_metrics")) //nvd/entry/cvss/base_metrics
                                {
                                    foreach (var basemetricsNodes in cvssNodes.SubNodes) //nvd/entry/cvss/base_metrics/...
                                    {
                                        string[] key = basemetricsNodes.Name.Split(':');
                                        if (key[1] == "score")
                                            cveEntry.Score = basemetricsNodes.Value;
                                        else if (key[1] == "access-vector")
                                            cveEntry.AccessVector = basemetricsNodes.Value;
                                        else if (key[1] == "access-complexity")
                                            cveEntry.AccessComplexity = basemetricsNodes.Value;
                                        else if (key[1] == "authentication")
                                            cveEntry.Authentication = basemetricsNodes.Value;
                                        else if (key[1] == "confidentiality-impact")
                                            cveEntry.ConfidentialityImpact = basemetricsNodes.Value;
                                        else if (key[1] == "integrity-impact")
                                            cveEntry.IntegrityImpact = basemetricsNodes.Value;
                                        else if (key[1] == "availability-impact")
                                            cveEntry.AvailablilityImpact = basemetricsNodes.Value;
                                        else if (key[1] == "generated-on-datetime")
                                            cveEntry.DateCreated = Convert.ToDateTime(basemetricsNodes.Value);
                                    }
                                }
                            }
                        }
                    }
                    if(!cveEntry.Save(conn))  //store entry
                        return -1;

                    productEntry.EntryId = cveEntry.GetId(conn);

                    if (!productEntry.Save(conn)) //store link b/w entry and product
                        return -1;
                }
            }
            catch (XMLParsingException e)
            {
                throw new Exception("XML Parsing error: "+ e.Message);
                return -1;
            }
            Console.WriteLine("Task Completed!!");

            return 0;
        }
    }
}
