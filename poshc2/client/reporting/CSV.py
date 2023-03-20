#!/usr/bin/env python3

from poshc2.server.Config import ReportsDirectory
from poshc2.server.Core import print_bad
from poshc2.server.database.Model import Task, MitreTTP
from poshc2.server.database.Helpers import get_data_frame, get_implant, get_task


def generate_csv(table):
    frame = get_data_frame(table)

    # convert the implant_id to Domain\User @ Hostname
    if table == Task:
        # TODO FIX
        for index, row in frame.iterrows():
            implant = get_implant(row[1])

            try:
                if frame.loc[index, "implant_id"]:
                    frame.loc[index, "implant_id"] = implant.domain + "\\" + implant.user + " @ " + implant.hostname
            except:
                try:
                    if frame.loc[index, "implant_id"]:
                        frame.loc[index, "implant_id"] = implant.domain + "\\" + implant.user + " @ " + implant.hostname
                except:
                    print("Cannot translate implant_id")
    elif table == MitreTTP:
        for index, row in frame.iterrows():
            task = get_task(row[4])
            implant = get_implant(task.implant_id)
            frame.loc[index, "context"] = implant.domain + "\\" + implant.user + " @ " + implant.hostname
            frame.loc[index, "timestamp"] = task.completed_time
            frame.loc[index, "command"] = task.command

        del frame["task_id"]

    csv_report_name = f"{ReportsDirectory}{table.__tablename__}.csv"
    output_csv = open(csv_report_name, 'w')
    CSV = (frame.to_csv(index=False, encoding='utf-8'))
    output_csv.write(CSV)
    output_csv.close()
    print(f"    {csv_report_name}")
