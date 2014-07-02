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
        // FIXME: this should be "Vendor", not "vendor", because public
        // instance attributes and properties start with capital letters in C#
        // (like Array.Length, for example).
        // Similar for other classes.
        public string vendor;
        public string product;

        public bool Save(MySqlConnection conn)
        {
            string sql = "INSERT INTO products(vendor, product) VALUES (@vendor_val,@product_val);";
            MySqlCommand insertProduct = new MySqlCommand(sql, conn);
            insertProduct.Parameters.AddWithValue("@vendor_val", vendor);
            insertProduct.Parameters.AddWithValue("@product_val", product);
            try
            {
                insertProduct.ExecuteScalar();
            }
            catch (MySqlException e)
            {
                Console.WriteLine("Error inserting row in Products Table: \n{0} - ", e.Message);
                return false;
            }
            return true;
        }

        public int GetId(MySqlConnection conn)
        {
            string sql = "SELECT product_id FROM products WHERE vendor = @vendor_val AND product = @product_val;";
            MySqlCommand cmd = new MySqlCommand(sql,conn);
            cmd.Parameters.AddWithValue("@vendor_val",vendor);
            cmd.Parameters.AddWithValue("@product_val", product);
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
    }

    // Structure to link a vulnerability to a product
    class ProductEntry
    {
        public HashSet<int> productIds = new HashSet<int>();
        public int entryId;

        public bool Save(MySqlConnection conn)
        {
            foreach (var product in productIds)
            {
                string sql = "INSERT INTO product_entries (product_id, entry_id) VALUES (@prod,@entry);";
                MySqlCommand insertProdEntry = new MySqlCommand(sql, conn);

                insertProdEntry.Parameters.AddWithValue("@entry", entryId);
                insertProdEntry.Parameters.AddWithValue("@prod", product); //fix

                try
                {
                    insertProdEntry.ExecuteScalar();
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

    // Stores info about a CVE vulnerability
    class CveEntry
    {
        // FIXME: Please remove underscores in attribute names, e.g.,
        // access_Vector -> AccessVector
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
            //store all info regarding one entry to database
            string sql = "INSERT INTO cve_entries(entry, cwe, summary, score, access_complexity,"+
            "access_vector, authentication, availability_impact, confidentiality_impact,"+
            "integrity_impact, date_created, published_date, last_modified) VALUES (@entry,@cwe,@summary,"+
            "@score,@ac,@av,@authentication,@ai,@ci,@ii,@date_created,@date_pub,@last_mod);";

            MySqlCommand insertEntry = new MySqlCommand(sql, conn);
            insertEntry.Parameters.AddWithValue("@entry",entry );
            insertEntry.Parameters.AddWithValue("@cwe", cwe);
            insertEntry.Parameters.AddWithValue("@summary",  summary);
            insertEntry.Parameters.AddWithValue("@score",  score);
            insertEntry.Parameters.AddWithValue("@ac",  access_Complexity);
            insertEntry.Parameters.AddWithValue("@av",  access_Vector);
            insertEntry.Parameters.AddWithValue("@authentication",  authentication);
            insertEntry.Parameters.AddWithValue("@ai",  availablility_Impact);
            insertEntry.Parameters.AddWithValue("@ci",  confidentiality_Impact);
            insertEntry.Parameters.AddWithValue("@ii",  integrity_Impact);
            insertEntry.Parameters.AddWithValue("@date_created",  date_Created);
            insertEntry.Parameters.AddWithValue("@date_pub",  date_Published);
            insertEntry.Parameters.AddWithValue("@last_mod",  last_Modified);

            // FIXME: Does this handle duplicate entries correctly? The goal is
            // to run this daily using the newest XML file, so it shoudl ignore
            // duplicates.
            try
            {
                insertEntry.ExecuteScalar();
            }
            catch (MySqlException e)
            {
                Console.WriteLine("Error inserting row in cve_entries Table: \n{0}", e.Message);
                return false;
            }
            return true;
        }

        public int GetId(MySqlConnection conn)
        {
            string sql = "SELECT entry_id FROM cve_entries WHERE entry = @entry_val ;";
            MySqlCommand cmd1 = new MySqlCommand(sql, conn);
            cmd1.Parameters.AddWithValue("@entry_val", entry);
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
                Console.WriteLine("XML File Not found. Details:\n" + e.Message);
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
                Console.WriteLine("App Config not found...");
                return false;
            }
            return true;
        }

        static int Main(string[] args)
        {
            if (args.Length < 2 )
            {
                Console.WriteLine("usage: Program.exe <Path\\to\\XML\\File.xml> <database password>");
                return -1;
            }

            if (!ReadAppConfig())
                return -1;

            else if (args[1] == null)
            {
                Console.WriteLine("Password not specified..");
                return -1;
            }

            // list of products and vendors for each entry
            HashSet<Product> product_Vendor = new HashSet<Product>();

            // FIXME: This should be at the same place where the
            // NanoXMLDocument xml is created?
            byte[] data = LoadXml(args[0]);
            string strData;
            if (data != null)
                strData = Encoding.UTF8.GetString(data);
            else
                return -1;

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
                NanoXMLDocument xml = new NanoXMLDocument(strData);

                foreach (var entryNode in xml.RootNode.SubNodes) //nvd/entry
                {
                    ProductEntry productEntry = new ProductEntry();
                    CveEntry cveEntry = new CveEntry(); //new object for very entry
                    cveEntry.entry = entryNode.GetAttribute("id").Value; //entry id= "bla-bla"
                    foreach (var entrySubNode in entryNode.SubNodes) //nvd/entry/...
                    {
                        if (entrySubNode.Name.Equals("vuln:published-datetime"))
                        {
                            cveEntry.date_Published = Convert.ToDateTime(entrySubNode.Value);
                        }
                        else if (entrySubNode.Name.Equals("vuln:last-modified-datetime"))
                        {
                            cveEntry.last_Modified = Convert.ToDateTime(entrySubNode.Value);
                        }
                        else if (entrySubNode.Name.Equals("vuln:vulnerable-software-list"))
                        {
                            foreach (var productNode in entrySubNode.SubNodes) //nvd/entry/software-list/product
                            {
                                string[] vendors = productNode.Value.Split(':');
                                Product tempProduct = new Product();
                                tempProduct.vendor = vendors[2]; //vendor name
                                tempProduct.product = vendors[3]; //product name

                                // FIXME: This could break if this program is
                                // called multiple times (with different XML
                                // files, or with the same file) and the
                                // product is already in the database. We
                                // probably don't need the product_Vendor set.
                                // Instead, we can store every product in the
                                // database and ignore duplicates.
                                bool flag = false;
                                foreach (var product_Row in product_Vendor) //checking duplicates for products
                                {
                                    if (product_Row.product == tempProduct.product && product_Row.vendor == tempProduct.vendor)
                                    flag = true;
                                }
                                if (!flag) //if instance not found, then try storing in database
                                {
                                    if(!tempProduct.Save(conn)) //store product
                                        return -1;
                                    product_Vendor.Add(tempProduct); // to check for duplicates\
                                }
                                productEntry.productIds.Add(tempProduct.GetId(conn)); //list of products' ids
                            }
                        }
                        else if (entrySubNode.Name.Equals("vuln:summary"))
                        {
                            cveEntry.summary = entrySubNode.Value; //summary
                        }
                        else if (entrySubNode.Name.Equals("vuln:cwe"))
                        {
                            cveEntry.cwe = entrySubNode.GetAttribute("id").Value; //cwe id
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
                                            cveEntry.score = basemetricsNodes.Value;
                                        else if (key[1] == "access-vector")
                                            cveEntry.access_Vector = basemetricsNodes.Value;
                                        else if (key[1] == "access-complexity")
                                            cveEntry.access_Complexity = basemetricsNodes.Value;
                                        else if (key[1] == "authentication")
                                            cveEntry.authentication = basemetricsNodes.Value;
                                        else if (key[1] == "confidentiality-impact")
                                            cveEntry.confidentiality_Impact = basemetricsNodes.Value;
                                        else if (key[1] == "integrity-impact")
                                            cveEntry.integrity_Impact = basemetricsNodes.Value;
                                        else if (key[1] == "availability-impact")
                                            cveEntry.availablility_Impact = basemetricsNodes.Value;
                                        else if (key[1] == "generated-on-datetime")
                                            cveEntry.date_Created = Convert.ToDateTime(basemetricsNodes.Value);
                                    }
                                }
                            }
                        }
                    }
                    if(!cveEntry.Save(conn))  //store entry
                        return -1;

                    productEntry.entryId = cveEntry.GetId(conn);

                    if (!productEntry.Save(conn)) //store link b/w entry and product
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
