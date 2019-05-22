﻿using amdocs.ginger.GingerCoreNET;
using Amdocs.Ginger.CoreNET.Execution;
using Amdocs.Ginger.CoreNET.LiteDBFolder;
using LiteDB;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ginger.Logger
{
    internal class WebReportGenerator
    {
        public bool RunNewHtmlReport(string runSetGuid = null, WebReportFilter openObject = null)
        {
            bool response = false;
            try
            {
                string clientAppFolderPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Reports\\Ginger-Web-Client");
                DeleteFoldersData(Path.Combine(clientAppFolderPath, "assets", "Execution_Data"));
                DeleteFoldersData(Path.Combine(clientAppFolderPath, "assets", "screenshots"));
                LiteDbManager dbManager = new LiteDbManager(WorkSpace.Instance.Solution.ExecutionLoggerConfigurationSetList.ExecutionLoggerConfigurationExecResultsFolder);
                var result = dbManager.GetRunSetLiteData();
                List<LiteDbRunSet> filterData = null;
                if (!string.IsNullOrEmpty(runSetGuid))
                {
                    filterData = result.IncludeAll().Find(a => a._id.ToString() == runSetGuid).ToList();
                }
                else
                    filterData = dbManager.FilterCollection(result, Query.All());
                LiteDbRunSet lightDbRunSet = filterData.Last();
                PopulateMissingFields(lightDbRunSet, clientAppFolderPath);
                string json = Newtonsoft.Json.JsonConvert.SerializeObject(filterData.Last());
                response = RunClientApp(json, clientAppFolderPath, openObject);
            }
            catch (Exception ex)
            {

            }
            return response;

        }

        private bool RunClientApp(string json, string clientAppFolderPath, WebReportFilter openObject)
        {
            bool response = false;

            try
            {
                StringBuilder pageDataSb = new StringBuilder();
                pageDataSb.Append("index.html");
                if (openObject != null)
                {
                    pageDataSb.Append("?Routed_Guid=");
                    pageDataSb.Append(openObject.Guid);
                }
                string taskCommand = $"{Path.Combine(clientAppFolderPath, pageDataSb.ToString())} --allow-file-access-from-files";
                System.IO.File.WriteAllText(Path.Combine(clientAppFolderPath, "assets\\Execution_Data\\executiondata.json"), json); //TODO - Replace with the real location under Ginger installation
                System.Diagnostics.Process.Start("chrome", taskCommand);
                response = true;
            }
            catch (Exception ec)
            {

            }
            return response;
        }

        private void DeleteFoldersData(string clientAppFolderPath)
        {
            DirectoryInfo dir = new DirectoryInfo(clientAppFolderPath);
            foreach (FileInfo fi in dir.GetFiles())
            {
                fi.Delete();
            }
        }

        //TODO move it to utils class
        private void PopulateMissingFields(LiteDbRunSet liteDbRunSet, string clientAppPath)
        {
            string imageFolderPath = Path.Combine(clientAppPath, "assets", "screenshots");

            int totalRunners = liteDbRunSet.RunnersColl.Count;
            int totalPassed = liteDbRunSet.RunnersColl.Where(runner => runner.RunStatus == eRunStatus.Passed.ToString()).Count();
            int totalExecuted = totalRunners - liteDbRunSet.RunnersColl.Where(runner => runner.RunStatus == eRunStatus.Pending.ToString() || runner.RunStatus == eRunStatus.Skipped.ToString() || runner.RunStatus == eRunStatus.Blocked.ToString()).Count();
            if (totalRunners != 0)
                liteDbRunSet.ExecutionRate = (totalExecuted * 100 / totalRunners).ToString();
            if (totalRunners != 0)
                liteDbRunSet.PassRate = (totalPassed * 100 / totalRunners).ToString();

            foreach (LiteDbRunner liteDbRunner in liteDbRunSet.RunnersColl)
            {

                int totalBFs = liteDbRunner.BusinessFlowsColl.Count;
                int totalPassedBFs = liteDbRunner.BusinessFlowsColl.Where(bf => bf.RunStatus == eRunStatus.Passed.ToString()).Count();
                int totalExecutedBFs = totalBFs - liteDbRunner.BusinessFlowsColl.Where(bf => bf.RunStatus == eRunStatus.Pending.ToString() || bf.RunStatus == eRunStatus.Skipped.ToString() || bf.RunStatus == eRunStatus.Blocked.ToString()).Count();
                if (totalBFs != 0)
                    liteDbRunner.ExecutionRate = (totalExecutedBFs * 100 / totalBFs).ToString();
                if (totalExecutedBFs != 0)
                    liteDbRunner.PassRate = (totalPassedBFs * 100 / totalExecutedBFs).ToString();

                foreach (LiteDbBusinessFlow liteDbBusinessFlow in liteDbRunner.BusinessFlowsColl)
                {
                    int totalActivities = liteDbBusinessFlow.ActivitiesColl.Count;
                    int totalPassedActivities = liteDbBusinessFlow.ActivitiesColl.Where(ac => ac.RunStatus == eRunStatus.Passed.ToString()).Count();
                    int totalExecutedActivities = totalActivities - liteDbBusinessFlow.ActivitiesColl.Where(ac => ac.RunStatus == eRunStatus.Pending.ToString() || ac.RunStatus == eRunStatus.Skipped.ToString() || ac.RunStatus == eRunStatus.Blocked.ToString()).Count();
                    if (totalActivities != 0)
                        liteDbBusinessFlow.ExecutionRate = (totalExecutedActivities * 100 / totalActivities).ToString();
                    if (totalExecutedActivities != 0)
                        liteDbBusinessFlow.PassRate = (totalPassedActivities * 100 / totalExecutedActivities).ToString();

                    foreach (LiteDbActivity liteDbActivity in liteDbBusinessFlow.ActivitiesColl)
                    {
                        int totalActions = liteDbActivity.ActionsColl.Count;
                        int totalPassedActions = liteDbActivity.ActionsColl.Where(ac => ac.RunStatus == eRunStatus.Passed.ToString()).Count();
                        int totalExecutedActions = totalActions - liteDbActivity.ActionsColl.Where(ac => ac.RunStatus == eRunStatus.Pending.ToString() || ac.RunStatus == eRunStatus.Skipped.ToString() || ac.RunStatus == eRunStatus.Blocked.ToString()).Count();
                        if (totalActions != 0)
                            liteDbActivity.ExecutionRate = (totalExecutedActions * 100 / totalActions).ToString();
                        if (totalExecutedActions != 0)
                            liteDbActivity.PassRate = (totalPassedActions * 100 / totalExecutedActions).ToString();

                        foreach (LiteDbAction liteDbAction in liteDbActivity.ActionsColl)
                        {
                            List<string> newScreenShotsList = new List<string>();
                            foreach (string screenshot in liteDbAction.ScreenShots)
                            {
                                string fileName = Path.GetFileName(screenshot);
                                string newScreenshotPath = Path.Combine(imageFolderPath, fileName);
                                System.IO.File.Copy(screenshot, newScreenshotPath, true); //TODO - Replace with the real location under Ginger installation
                                newScreenShotsList.Add(fileName);
                            }
                            liteDbAction.ScreenShots = newScreenShotsList;
                        }
                    }

                }
            }
        }

    }
}
