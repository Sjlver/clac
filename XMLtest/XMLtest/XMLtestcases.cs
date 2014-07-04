using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using XMLParser;
using MySql.Data.MySqlClient;
using System.Configuration;
using System.Collections.Generic;
using System.IO;
using System.Text;


namespace XMLtest
{
    [TestClass]
    public class XMLtestcases
    {
        public string[] args = new string[2];

        public void EmptyDataBase()
        {
            string sql1 = "DELETE FROM product_entries;";
            string sql2 = "DELETE FROM products;";
            string sql3 = "DELETE FROM cve_entries;";
            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand emptydb1 = new MySqlCommand(sql1, conn);
            MySqlCommand emptydb2 = new MySqlCommand(sql2, conn);
            MySqlCommand emptydb3 = new MySqlCommand(sql3, conn);
           
            try
            {
                emptydb1.ExecuteScalar();
                emptydb2.ExecuteScalar();
                emptydb3.ExecuteScalar();
            }
            catch (MySqlException e)
            {
               
                    throw new Exception("Error Cleaning up Database. \n" + e.Message);
            }
        }
        public string GetScore()
        {
            string sql = "SELECT score from cve_entries";
            
            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getscore = new MySqlCommand(sql, conn);
            return Convert.ToString( getscore.ExecuteScalar());
            
          
        }
        public int RowCountProducts()
        {
            string sql = "SELECT COUNT(*) from products";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getrowcount = new MySqlCommand(sql, conn);


            
                return Convert.ToInt32(getrowcount.ExecuteScalar());

        }
        public int RowCountCveEntries()
        {
            string sql = "SELECT COUNT(*) from cve_entries";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getrowcount = new MySqlCommand(sql, conn);
            return Convert.ToInt32(getrowcount.ExecuteScalar());

        }
        public string GetAC()
        {
            string sql = "SELECT access_complexity from cve_entries ";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getAC= new MySqlCommand(sql, conn);


            
                return Convert.ToString(getAC.ExecuteScalar());

        }
        public string GetCI()
        {
            string sql = "SELECT confidentiality_impact from cve_entries ";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getCI = new MySqlCommand(sql, conn);


                return Convert.ToString(getCI.ExecuteScalar());

            
        }
        public string GetII()
        {
            string sql = "SELECT integrity_impact from cve_entries";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getII = new MySqlCommand(sql, conn);


            return Convert.ToString(getII.ExecuteScalar());


        }
        public string GetCWE()
        {
            string sql = "SELECT cwe from cve_entries ";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getcwe = new MySqlCommand(sql, conn);


            return Convert.ToString(getcwe.ExecuteScalar());


        }
        public DateTime GetDate()
        {
            string sql = "SELECT last_modified from cve_entries";

            string connectionString = "server=" + ConfigurationManager.AppSettings.Get("server") +
                   ";user=" + ConfigurationManager.AppSettings.Get("user") +
                   ";database=" + ConfigurationManager.AppSettings.Get("database") +
                   ";port=" + ConfigurationManager.AppSettings.Get("port") +
                   ";password=" + "cves" + ";";
            MySqlConnection conn = new MySqlConnection(connectionString);

            conn.Open();
            MySqlCommand getdate = new MySqlCommand(sql, conn);
            return Convert.ToDateTime(getdate.ExecuteScalar());
        }

        [TestMethod]
        public void InvalidXMLPath()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\VisualStudio 2012\\Projects\\XMLtest\\XMLtest\\TestCases\\ValidXMLUnit.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.IsTrue(e is DirectoryNotFoundException,"Program must throw an exception of type DirectoryNotFound.");
            }

            
        }
        [TestMethod]
        public void MissingPassword()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\ValidXMLUnit.xml";
            args[1] = null;

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch(Exception e)
            {
                Assert.IsTrue(e is MissingFieldException, "Program must throw an exception of type MissingField because password is Missing.");
            }

        }
        [TestMethod]
        public void InvalidPassword()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\ValidXMLUnit.xml";
            args[1] = "BLAH";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch(MySqlException e){
                Assert.IsTrue(e is MySqlException, "Program must identify invalid password by throwing an SQLexception");
            }

        }
        [TestMethod]
        public void MissingNVDClosingTag()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidXMLFormat.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {

                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
           catch (Exception e)
            {
                Assert.IsTrue(e is XMLParsingException, "Program should Throw an XMLParsing exception" );
            }

        }
        [TestMethod]
        public void SameProductNames()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidValues5.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {

                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual(1, RowCountProducts(), "# of Rows Should be equal to 1 in case of duplicate entries.");
            }

        }
        [TestMethod]
        public void InvalidScoreValue()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidValues4.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("0", GetScore(), "Upon Invalid Score Value, Value stored in Database Must be equal to 0.");
                //FIND FROM DB
            }

        }
        [TestMethod]
        public void MissingACValue()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidValues3.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("", GetAC(), "Theere should have been a null in place of access complexity in case of missing tag.");
            }

        }
        [TestMethod]
        public void InvalidCIValue()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidValues2.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("", GetCI(), "Incase of Invalid value, Empty string should have been saved in db.");
            }

        }
        [TestMethod]
        public void InvalidDateFormat()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidValues.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual(Convert.ToDateTime("1/1/0001"),GetDate(),"Incase of Invalid date, Value in db must be default date"); //CHECK
            }

        }
        [TestMethod]
        public void SameCVEIds()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\InvalidValues6.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual(1, RowCountCveEntries(), "Row count must be 1 in case of Duplicate Entries in cve_Entries.");
            }


        }
        [TestMethod]
        public void MissingCWE()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingValues3.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("",GetCWE(),"Value stored in db must be equal to null in case of absnece of cwe tag.");
            }

        }
        [TestMethod]
        public void MissingCWEId()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingValues2.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("", GetCWE(), "Value stored in db must be equal to empty string in case of absence of cwe id.");
            }

        }
        [TestMethod]
        public void MissingEntryId()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingValues.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            } catch (MySqlException e) {
                Assert.AreEqual(1048, e.Number, "Parser must throw an exception with code 1048 if no CVE id is present.");

            }
        }
        [TestMethod]
        public void MissingSoftwareList()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingTag4.xml";
            args[1] = "cves";

            EmptyDataBase();

            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual(0, RowCountProducts(), "No rows must be added in Products table in case of absence of software list.");
            }

        }
        [TestMethod]
        public void MissingScoreTag()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingTag3.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("", GetScore(), "Value stored in db must be equal to null in case of absence of score tag.");
            }

        }
        [TestMethod]
        public void MissingII()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingTag2.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual("", GetII(), "Value stored in db must be equal to null in case of absenece of II tag.");
            }

        }
        [TestMethod]
        public void MissingPublishedDate()
        {
            args[0] = "C:\\Users\\Azqa\\Documents\\GitHub\\clac\\XMLtest\\XMLtest\\TestCases\\MissingTag.xml";
            args[1] = "cves";

            EmptyDataBase();
            try
            {
                XMLparser.Main(args);
                Assert.Fail("No exception was thrown");
            }
            catch (Exception e)
            {
                Assert.AreEqual(Convert.ToDateTime("1/1/0001"), GetDate(), "Value stored in db must be equal to null in case of absenece of last_modified tag.");
            }

        }
    
    }
}
