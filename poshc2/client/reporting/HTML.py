#!/usr/bin/env python3
import os, sys, codecs, json, subprocess, time, base64
from poshc2.server.Config import ReportsDirectory, ReportingDirectory, ImagesDirectory, PayloadCommsHost, DatabaseType
from poshc2.server.database.DB import get_html_report_data, get_implants_all
from poshc2.server.database.DBType import DBType
from poshc2.client.reporting.ReportColumns import ReportColumns
from poshc2.client.reporting.ReportKeys import ReportKeys


def generate_html_table(table_name):
    base = codecs.open(f"{ReportingDirectory}HTML_Template.html", 'r', 'utf-8').read()
    report_logo = open(f"{ImagesDirectory}ReportLogo.png", "rb")
    report_logo = str(base64.b64encode(report_logo.read()).decode('utf-8'))
    posh_logo = open(f"{ImagesDirectory}PoshC2Logo.png", "rb")
    posh_logo = str(base64.b64encode(posh_logo.read()).decode('utf-8'))
    columns = ReportColumns[table_name].value
    data = get_table_data(table_name)
    base = base.replace('__TITLE__', table_name)
    base = base.replace('__TABLECOLUMNS__', columns)
    base = base.replace('__TABLEDATA__', data)
    base = base.replace('__REPORTLOGO__', report_logo)
    base = base.replace('__POSHLOGO__', posh_logo)
    report_name = f"{ReportsDirectory}{table_name}.html"
    output_file = open(report_name, 'w')
    output_file.write(base)
    output_file.close()
    print(report_name)


def get_table_data(table_name):
    frame = get_html_report_data(table_name)
    if (frame is None):
        return "[]"

    if (DatabaseType == DBType.Postgres):
        output = table_data_postgres(frame, table_name)
        return output
    if (DatabaseType == DBType.SQLite):
        output = table_data_sqlite(frame)
        return output
    return "[]"


def table_data_postgres(frame, table_name):
    keys = ReportKeys[table_name].value
    output = []
    for row in frame:
        rowObj = {}
        for idx, key in enumerate(keys):
            rowObj[key] = str(row[idx]).replace("</script>", "<\/script>")
        output.append(rowObj)
    return json.dumps(output)


def table_data_sqlite(frame):
    keys = frame[0].keys()
    output = []
    for row in frame:
        rowObj = {}
        for key in keys:
            rowObj[key] = str(row[key]).replace("</script>", "<\/script>")
        output.append(rowObj)
    return json.dumps(output)


def graphviz():
    GV = """
digraph "PoshC2" {

  subgraph proxy {
      node [color=white, fontcolor=red, fontsize=15, shapefile="%s/firewall.png"];
      "POSHSERVER";
  }

  subgraph implant {
      node [color=white, fontcolor=white, fontsize=15, shapefile="%s/implant.png"];
      IMPLANTHOSTS
  }

  subgraph daisy {
      node [color=white, fontcolor=white, fontsize=15, shapefile="%s/implant.png"];
      DAISYHOSTS
  }

}
  """ % (ImagesDirectory, ImagesDirectory, ImagesDirectory)

    ServerTAG = "\\n\\n\\n\\n\\n\\n\\n\\n\\n\\nPoshC2 Server\\n%s" % PayloadCommsHost.replace("\"", "")
    GV = GV.replace("POSHSERVER", ServerTAG)

    implants = get_implants_all()
    hosts = ""
    daisyhosts = ""

    for implant in implants:
        if "Daisy" not in implant.Pivot:
            if implant.Hostname not in hosts:
                domain = implant.Domain.replace("\\", "\\\\")
                hosts += "\"%s\" -> \"%s \\n %s\\n\\n\\n\\n \"; \n" % (ServerTAG, domain, implant.Hostname)
        else:
            domain = implant.Domain.replace("\\", "\\\\")
            if "\"%s\\n\\n\\n\\n \" -> \"%s \\n %s\\n\\n\\n\\n \"; \n" % (implant.Pivot.replace('\x00', '').replace("\\", "\\\\").replace('@', ' \\n '), domain, implant.Hostname) not in daisyhosts:
                daisyhosts += "\"%s\\n\\n\\n\\n \" -> \"%s \\n %s\\n\\n\\n\\n \"; \n" % (implant.Pivot.replace('\x00', '').replace("\\", "\\\\").replace('@', ' \\n '), domain, implant.Hostname)

    GV = GV.replace("DAISYHOSTS", daisyhosts)
    GV = GV.replace("IMPLANTHOSTS", hosts)
    output_file = open("%sPoshC2.dot" % ReportsDirectory, 'w')
    output_file.write("%s" % GV)
    output_file.close()
    subprocess.check_output("dot -T png -o %sPoshC2.png %sPoshC2.dot" % (ReportsDirectory, ReportsDirectory), shell=True)
    print("")
    print("GraphViz Generated PoshC2.png")
    time.sleep(1)
