#!/usr/bin/env python3
from poshc2.server.Config import ReportsDirectory
from poshc2.server.database.DB import get_implantbyrandomuri, get_alldata

def generate_csv(table):
    frame = get_alldata(table)

    # convert the randomuri to Domain\User @ Hostname
    if table.lower() == "tasks":
        for index, row in frame.iterrows():
            implant = get_implantbyrandomuri(row[1])
            try:
                if frame.loc[index, "randomuri"]:
                    frame.loc[index, "randomuri"] = implant.Domain + "\\" + implant.User + " @ " + implant.Hostname
            except:
                try:
                    if frame.loc[index, "RandomURI"]:
                        frame.loc[index, "RandomURI"] = implant.Domain + "\\" + implant.User + " @ " + implant.Hostname 
                except:
                    print("Cannot translate RandomURI")

    csvreportname = "%s%s.csv" % (ReportsDirectory, table)
    output_csv = open(csvreportname, 'w')
    CSV = (frame.to_csv(index=False, encoding='utf-8'))
    output_csv.write(CSV)
    output_csv.close()
    print(csvreportname)
