# Service Permission Checker && Folder Perms Checker
# Ben Turner @benpturner

<#
.Synopsis
    Service Permission Checker

.DESCRIPTION
	Permission Checker : Equivlent to:

    $_.FullName | Select-Object pschildname,pspath,accesstostring} catch{}}|Export-Csv C:\temp\acl.csv -NoTypeInformation

.EXAMPLE
    PS C:\> Get-ServicePerms
    
#>
Function Get-ServicePerms {

$csharp= @"
using System;
using System.Data;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Management;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml;
using System.Collections;
using System.ServiceProcess;
using System.Net;

public static class ServicePerms

    {
        static List<string> folderlist;
        public static void dumpfolderperms(List<string> folderlist, DataSet ds)
        {
            //DataSet ds = new DataSet();
            ds.Tables.Add("folders");
            ds.Tables["folders"].Columns.Add("Folder");
            ds.Tables["folders"].Columns.Add("Permissions");
            string permstring = null;
            string cpermstring = null; 

            foreach (string value in folderlist)
            {
                permstring = null;
                cpermstring = null;
                try
                {
                    FileSecurity fileSecurity = new FileSecurity(value, AccessControlSections.Access);
                    AuthorizationRuleCollection arc = fileSecurity.GetAccessRules(true, true, typeof(NTAccount));
                    foreach (FileSystemAccessRule rule in arc)
                    {

                        permstring = "";
                        permstring = rule.IdentityReference + " " + rule.AccessControlType + " " + rule.FileSystemRights;

                        // is this case sensitive
                        if (permstring.Contains("Users") & permstring.Contains("Modify"))
                        {
                            permstring = "<b><div style=\"color:red;\">**" + permstring + "</div></b>";
                        }
                        if (permstring.Contains("Users") & permstring.Contains("FullControl"))
                        {
                            permstring = "<b><div style=\"color:red;\">**" + permstring + "</div></b>";
                        }
                        if (permstring.Contains("Everyone") & permstring.Contains("Modify"))
                        {
                            permstring = "<b><div style=\"color:red;\">**" + permstring + "</div></b>";
                        }
                        if (permstring.Contains("Everyone") & permstring.Contains("FullControl"))
                        {
                            permstring = "<b><div style=\"color:red;\">**" + permstring + "</div></b>";
                        }

                        cpermstring = cpermstring + permstring + " <br>";

                    }

                    }
                    catch
                    {

                    }

                ds.Tables["folders"].Rows.Add(value, cpermstring);
            }
            String hostName = Dns.GetHostName();
            string contents = ConvertDataTableToHtml(ds.Tables["services"]);
            string contentsfolders = ConvertDataTableToHtml2(ds.Tables["folders"]);
            File.WriteAllText("Report-" + hostName + ".html", contents + contentsfolders);
        }

        public static void dumpservices()
        {
            String hostName = Dns.GetHostName();
            List<string> list = new List<string>();
            folderlist = new List<string>();
            //List<string> folderlist = new List<string>();
            DataSet ds = new DataSet();
            ds.Tables.Add("services");
            ds.Tables["services"].Columns.Add("Service Name");
            ds.Tables["services"].Columns.Add("Unquoted");
            ds.Tables["services"].Columns.Add("ImagePath");
            ds.Tables["services"].Columns.Add("Permissions");
            ds.Tables["services"].Columns.Add("Service Information");

            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Service");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject queryObj in searcher.Get())
            {
                String input = "";
                try {
                    if (queryObj["PathName"].ToString() == "") {
                    continue;
                    } else {
                    input = queryObj["PathName"].ToString();
                    }
                } catch {
                }
                string key = "";
                string unquoted = "";

                Match match = Regex.Match(input, @"^(.+?).exe", RegexOptions.IgnoreCase);

                // Here we check the Match instance.
                if (match.Success)
                {

                    //Check for unquotes service paths
                    string unqu = match.Groups[1].Value + ".exe";
                    if (!unqu.Contains("\"") && unqu.Contains(" "))
                    {
                        unquoted = "Unquoted**";
                    }
                    else
                    {
                        unquoted = "False";
                    }

                    // Finally, we get the Group value and display it.
                    key = match.Groups[1].Value + ".exe";
                    key = key.Replace("\"", "");
                    string permsstring = null;
                    string currentpermstring = null;
                    try
                    {
                        FileSecurity fileSecurity = new FileSecurity(key, AccessControlSections.Access);
                        var file_info = new FileInfo(key);
                        //file_info.Directory.Parent
                        
                        AuthorizationRuleCollection arc = fileSecurity.GetAccessRules(true, true, typeof(NTAccount));
                        foreach (FileSystemAccessRule rule in arc)
                        {
                            // find if users modify
                            // if it contains everyone or users with modify or fullControl then flag as bold or something.....
                            // or search through the html after.....
                            currentpermstring = "";
                            currentpermstring = rule.IdentityReference + " " + rule.AccessControlType + " " + rule.FileSystemRights;

                            // is this case sensitive
                            if (currentpermstring.Contains("Users") & currentpermstring.Contains("Modify"))
                            {
                                currentpermstring = "<b><div style=\"color:red;\">**" + currentpermstring + "</div></b>";
                            }
                            if (currentpermstring.Contains("Users") & currentpermstring.Contains("FullControl"))
                            {
                                currentpermstring = "<b><div style=\"color:red;\">**" + currentpermstring + "</div></b>";
                            }
                            if (currentpermstring.Contains("Everyone") & currentpermstring.Contains("Modify"))
                            {
                                currentpermstring = "<b><div style=\"color:red;\">**" + currentpermstring + "</div></b>";
                            }
                            if (currentpermstring.Contains("Everyone") & currentpermstring.Contains("FullControl"))
                            {
                                currentpermstring = "<b><div style=\"color:red;\">**" + currentpermstring + "</div></b>";
                            }

                            permsstring = permsstring + currentpermstring + " <br>";

                        }
                    }
                    catch
                    {
                        permsstring = "Path not found: " + key + "\n";
                    }

                    var key2 = "";

                    Match match2 = Regex.Match(key, @"^(.*[\\\/])[^\\\/]*$", RegexOptions.IgnoreCase);

                    if (match2.Success)
                    {
                        key2 = match2.Groups[1].ToString();

                    }

                    
                    var file = new FileInfo(key);
                    var directory2 = file.Directory;

                    while (directory2 != null)
                    {

                        if (!folderlist.Contains(directory2.FullName.ToString().ToLower()))
                        {
                            folderlist.Add(directory2.FullName.ToString().ToLower());
                        }

                        directory2 = directory2.Parent;

                    }


                    string serviceinformation = "";
                    // Try and see if the service can be stopped or restarted
                    
                    ServiceController svc = new ServiceController(queryObj["Name"].ToString());
                    try
                    {
                        serviceinformation = svc.Status.ToString();
                        bool canstop = svc.CanPauseAndContinue;
                        bool canstart = svc.CanStop;
                        bool canshutdown = svc.CanShutdown;
                        serviceinformation = serviceinformation + "<br>CanPauseAndContinue:" + canstop + "<br>CanStart:" + canstart + "<br>CanShutdown:" + canshutdown;

                        //svc.Start();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error" + ex);
                    }

                    ds.Tables["services"].Rows.Add(queryObj["DisplayName"].ToString() + " (" + queryObj["Name"].ToString() + ")", unquoted, queryObj["PathName"].ToString(), permsstring, serviceinformation);
                }

            }
            DirSearch("C:\\");
            dumpfolderperms(folderlist, ds);

        }
        public static void DirSearch(string sDir)
        {
            try
            {
                foreach (string d in Directory.GetDirectories(sDir))
                {
                    folderlist.Add(d);
                    DirSearch(d);
                }
            }
            catch (System.Exception excpt)
            {
                Console.WriteLine(excpt.Message);
            }
        }
        public static string ConvertDataTableToHtml(DataTable targetTable)
        {
            if (targetTable == null)
            {
                throw new ArgumentNullException("targetTable");
            }
            StringBuilder builder = new StringBuilder();
            builder.Append("<html>");
            builder.Append("<head>");
            builder.Append("<title>");
            builder.Append("Page-");
            builder.Append(Guid.NewGuid().ToString());
            builder.Append("</title>");
            builder.Append("</head>");
            builder.Append("<body>");
            builder.Append("<h1>Service Permissions - Search for ** to find any vulnerabilities........</h1>");
            builder.Append("<table border='1px' cellpadding='5' cellspacing='0' ");
            builder.Append("style='border: solid 1px Black; font-size: small;'>");
            builder.Append("<tr align='left' valign='top'>");
            foreach (DataColumn column in targetTable.Columns)
            {
                builder.Append("<td align='left' valign='top'>");
                builder.Append(column.ColumnName);
                builder.Append("</td>");
            }
            builder.Append("</tr>");
            foreach (DataRow row in targetTable.Rows)
            {
                builder.Append("<tr align='left' valign='top'>");
                foreach (DataColumn column2 in targetTable.Columns)
                {
                    builder.Append("<td align='left' valign='top'>");
                    builder.Append(row[column2.ColumnName].ToString());
                    builder.Append("</td>");
                }
                builder.Append("</tr>");
            }
            builder.Append("</table>");
            builder.Append("</body>");
            builder.Append("</html>");
            return builder.ToString();
        }
        
        public static string ConvertDataTableToHtml2(DataTable targetTable)
        {
            if (targetTable == null)
            {
                throw new ArgumentNullException("targetTable");
            }
            StringBuilder builder = new StringBuilder();
            builder.Append("<html>");
            builder.Append("<head>");
            builder.Append("<title>");
            builder.Append("Page-");
            builder.Append(Guid.NewGuid().ToString());
            builder.Append("</title>");
            builder.Append("</head>");
            builder.Append("<body>");
            builder.Append("<table border='1px' cellpadding='5' cellspacing='0' ");
            builder.Append("style='border: solid 1px Black; font-size: small;'>");
            builder.Append("<tr align='left' valign='top'>");
            foreach (DataColumn column in targetTable.Columns)
            {
                builder.Append("<td align='left' valign='top'>");
                builder.Append(column.ColumnName);
                builder.Append("</td>");
            }
            builder.Append("</tr>");
            foreach (DataRow row in targetTable.Rows)
            {
                builder.Append("<tr align='left' valign='top'>");
                foreach (DataColumn column2 in targetTable.Columns)
                {
                    builder.Append("<td align='left' valign='top'>");
                    builder.Append(row[column2.ColumnName].ToString());
                    builder.Append("</td>");
                }
                builder.Append("</tr>");
            }
            builder.Append("</table>");
            builder.Append("</body>");
            builder.Append("</html>");
            return builder.ToString();
        }
}

"@
$Assem = "System.Data",
"System.Xml.Linq",
"System.Xml",
"System.Data.Entity",
"System.Management",
"System.Management.Instrumentation",
"System.ServiceProcess"

Add-Type -TypeDefinition $csharp -Language CSharpVersion3 -IgnoreWarnings -ReferencedAssemblies $Assem

[ServicePerms]::dumpservices()
$complete = "[+] Writing output to Report-" + $env:COMPUTERNAME + ".html"
echo "[+] Completed Service Permissions Review"
echo "$complete"

}
