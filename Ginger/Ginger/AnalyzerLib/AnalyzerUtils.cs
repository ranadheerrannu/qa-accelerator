﻿using amdocs.ginger.GingerCoreNET;
using Amdocs.Ginger.Common;
using Ginger.Run;
using Ginger.SolutionGeneral;
using GingerCore;
using GingerCore.Actions;
using GingerCore.DataSource;
using GingerCore.Variables;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ginger.AnalyzerLib
{
    public class AnalyzerUtils
    {
        public void RunSolutionAnalyzer(Solution solution, ObservableList<AnalyzerItemBase> issuesList)
        {
            foreach (AnalyzerItemBase issue in AnalyzeSolution.Analyze(solution))
            {
                issuesList.Add(issue);
            }

            //TODO: once this analyzer is taking long time due to many checks, run it using parallel
            ObservableList<BusinessFlow> BFs = WorkSpace.Instance.SolutionRepository.GetAllRepositoryItems<BusinessFlow>();
            List<string> usedVariablesInSolution = new List<string>();

            foreach (BusinessFlow BF in BFs)
            {
                List<string> tempList = RunBusinessFlowAnalyzer(BF, issuesList);
                usedVariablesInSolution.AddRange(tempList);
            }
            ReportUnusedVariables(solution, usedVariablesInSolution, issuesList);
        }

        public void RunRunSetConfigAnalyzer(RunSetConfig mRunSetConfig, ObservableList<AnalyzerItemBase> issuesList)
        {
            foreach (AnalyzerItemBase issue in RunSetConfigAnalyzer.Analyze(mRunSetConfig))
            {
                issuesList.Add(issue);
            }

            // Check all GRs BFS
            foreach (GingerRunner GR in mRunSetConfig.GingerRunners)
            {
                foreach (AnalyzerItemBase issue in AnalyzeGingerRunner.Analyze(GR, WorkSpace.Instance.Solution.ApplicationPlatforms))
                {
                    issuesList.Add(issue);
                }

                //Code to analyze Runner Unique Businessflow with Source BF
                List<Guid> checkedGuidList = new List<Guid>();
                foreach (BusinessFlow BF in GR.BusinessFlows)
                {
                    if (!checkedGuidList.Contains(BF.Guid))//check if it already was analyzed
                    {
                        checkedGuidList.Add(BF.Guid);
                        BusinessFlow actualBf = WorkSpace.Instance.SolutionRepository.GetAllRepositoryItems<BusinessFlow>().Where(x => x.Guid == BF.Guid).FirstOrDefault();
                        if (actualBf != null)
                        {
                            RunBusinessFlowAnalyzer(actualBf, issuesList);
                        }
                    }
                }

                //Code to analyze Runner BF i.e. BFFlowControls
                foreach (BusinessFlow BF in GR.BusinessFlows)
                {
                    foreach (AnalyzerItemBase issue in AnalyzeRunnerBusinessFlow.Analyze(GR, BF))
                    {
                        issuesList.Add(issue);
                    }
                }
            }
        }


        public List<string> RunBusinessFlowAnalyzer(BusinessFlow businessFlow, ObservableList<AnalyzerItemBase> issuesList)
        {
            List<string> usedVariablesInBF = new List<string>();
            List<string> usedVariablesInActivity = new List<string>();

            ObservableList<DataSourceBase> DSList = WorkSpace.Instance.SolutionRepository.GetAllRepositoryItems<DataSourceBase>();
            foreach (AnalyzerItemBase issue in AnalyzeBusinessFlow.Analyze(WorkSpace.Instance.Solution, businessFlow))
            {
                issuesList.Add(issue);
            }

            Parallel.ForEach(businessFlow.Activities, new ParallelOptions { MaxDegreeOfParallelism = 5 }, activity =>
            { 
                 foreach (AnalyzerItemBase issue in AnalyzeActivity.Analyze(businessFlow, activity))
                 {
                     issuesList.Add(issue);
                 }

                 Parallel.ForEach(activity.Acts, new ParallelOptions { MaxDegreeOfParallelism = 5 }, iaction =>
                 {

                     Act action = (Act)iaction;
                     foreach (AnalyzerItemBase issue in AnalyzeAction.Analyze(businessFlow, activity, action, DSList))
                     {
                         issuesList.Add(issue);
                     }

                     List<string> tempList = AnalyzeAction.GetUsedVariableFromAction(action);
                     usedVariablesInActivity.AddRange(tempList);
                 });

                 List<string> activityVarList = AnalyzeActivity.GetUsedVariableFromActivity(activity);
                 usedVariablesInActivity.AddRange(activityVarList);
                 ReportUnusedVariables(activity, usedVariablesInActivity, issuesList);
                 usedVariablesInBF.AddRange(usedVariablesInActivity);
                 usedVariablesInActivity.Clear();
            });
            ReportUnusedVariables(businessFlow, usedVariablesInBF, issuesList);

            return usedVariablesInBF;
        }

        public void ReportUnusedVariables(object obj, List<string> usedVariables, ObservableList<AnalyzerItemBase> issuesList)
        {
            Solution solution = null;
            BusinessFlow businessFlow = null;
            Activity activity = null;
            string variableSourceType = "";
            string variableSourceName = "";
            ObservableList<VariableBase> AvailableAllVariables = new ObservableList<VariableBase>();
            if (typeof(BusinessFlow).Equals(obj.GetType()))
            {
                businessFlow = (BusinessFlow)obj;
                if (businessFlow.Variables.Count > 0)
                {
                    AvailableAllVariables = businessFlow.Variables;
                    variableSourceType = GingerDicser.GetTermResValue(eTermResKey.BusinessFlow);
                    variableSourceName = businessFlow.Name;
                }
            }
            else if (typeof(Activity).Equals(obj.GetType()))
            {
                activity = (Activity)obj;
                if (activity.Variables.Count > 0)
                {
                    AvailableAllVariables = activity.Variables;
                    variableSourceType = GingerDicser.GetTermResValue(eTermResKey.Activity);
                    variableSourceName = activity.ActivityName;
                }
            }
            else if (typeof(Solution).Equals(obj.GetType()))
            {
                solution = (Solution)obj;
                AvailableAllVariables = solution.Variables;
                variableSourceType = "Solution";
                variableSourceName = solution.Name;
            }

            foreach (VariableBase var in AvailableAllVariables)
            {
                if (usedVariables != null && (!usedVariables.Contains(var.Name)))
                {
                    if (obj.GetType().Equals(typeof(BusinessFlow)))
                    {
                        AnalyzeBusinessFlow aa = new AnalyzeBusinessFlow();
                        aa.Status = AnalyzerItemBase.eStatus.NeedFix;
                        aa.ItemName = var.Name;
                        aa.Description = var + " is Unused in " + variableSourceType + ": " + businessFlow.Name;
                        aa.Details = variableSourceType;
                        aa.mBusinessFlow = businessFlow;
                        aa.ItemParent = variableSourceName;
                        aa.CanAutoFix = AnalyzerItemBase.eCanFix.Yes;
                        aa.IssueType = AnalyzerItemBase.eType.Error;
                        aa.FixItHandler = DeleteUnusedVariables;
                        aa.Severity = AnalyzerItemBase.eSeverity.Medium;
                        issuesList.Add(aa);
                    }
                    else if (obj.GetType().Equals(typeof(Solution)))
                    {
                        AnalyzeSolution aa = new AnalyzeSolution();
                        aa.Status = AnalyzerItemBase.eStatus.NeedFix;
                        aa.ItemName = var.Name;
                        aa.Description = var + " is Unused in Solution";
                        aa.Details = variableSourceType;
                        aa.ItemParent = variableSourceName;
                        aa.CanAutoFix = AnalyzerItemBase.eCanFix.Yes;
                        aa.IssueType = AnalyzerItemBase.eType.Error;
                        aa.FixItHandler = DeleteUnusedVariables;
                        aa.Severity = AnalyzerItemBase.eSeverity.Medium;
                        issuesList.Add(aa);
                    }
                    else
                    {
                        AnalyzeActivity aa = new AnalyzeActivity();
                        aa.Status = AnalyzerItemBase.eStatus.NeedFix;
                        aa.ItemName = var.Name;
                        aa.Description = var + " is Unused in " + variableSourceType + ": " + activity.ActivityName;
                        aa.Details = variableSourceType;
                        aa.mActivity = activity;
                        //aa.mBusinessFlow = businessFlow;
                        aa.ItemParent = variableSourceName;
                        aa.CanAutoFix = AnalyzerItemBase.eCanFix.Yes;
                        aa.IssueType = AnalyzerItemBase.eType.Error;
                        aa.FixItHandler = DeleteUnusedVariables;
                        aa.Severity = AnalyzerItemBase.eSeverity.Medium;
                        issuesList.Add(aa);
                    }
                }
            }
        }

        private static void DeleteUnusedVariables(object sender, EventArgs e)
        {
            if (sender.GetType().Equals(typeof(AnalyzeActivity)))
            {
                Activity activity = ((AnalyzeActivity)sender).mActivity;
                foreach (VariableBase var in activity.Variables)
                {
                    if (var.Name.Equals(((AnalyzeActivity)sender).ItemName))
                    {
                        activity.Variables.Remove(var);
                        activity.RefreshVariablesNames();
                        ((AnalyzeActivity)sender).Status = AnalyzerItemBase.eStatus.Fixed;
                        break;
                    }
                }
            }
            else if (sender.GetType().Equals(typeof(AnalyzeBusinessFlow)))
            {
                BusinessFlow BFlow = ((AnalyzeBusinessFlow)sender).mBusinessFlow;
                foreach (VariableBase var in BFlow.Variables)
                {
                    if (var.Name.Equals(((AnalyzeBusinessFlow)sender).ItemName))
                    {
                        BFlow.Variables.Remove(var);
                        ((AnalyzeBusinessFlow)sender).Status = AnalyzerItemBase.eStatus.Fixed;
                        break;
                    }
                }
            }
            else if (sender.GetType().Equals(typeof(AnalyzeSolution)))
            {
                foreach (VariableBase var in BusinessFlow.SolutionVariables)
                {
                    if (var.Name.Equals(((AnalyzeSolution)sender).ItemName))
                    {
                        BusinessFlow.SolutionVariables.Remove(var);
                        ((AnalyzeSolution)sender).Status = AnalyzerItemBase.eStatus.Fixed;
                        break;
                    }
                }
            }
        }
    }
}
