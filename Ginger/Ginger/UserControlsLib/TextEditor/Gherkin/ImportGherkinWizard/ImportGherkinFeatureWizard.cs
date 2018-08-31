#region License
/*
Copyright © 2014-2018 European Support Limited

Licensed under the Apache License, Version 2.0 (the "License")
you may not use this file except in compliance with the License.
You may obtain a copy of the License at 

http://www.apache.org/licenses/LICENSE-2.0 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License. 
*/
#endregion

using Ginger.GherkinLib;
using GingerCore;
using GingerWPF.WizardLib;
using System;
using System.IO;
using static Ginger.GherkinLib.ImportGherkinFeatureFilePage;

namespace Ginger.UserControlsLib.TextEditor.Gherkin
{
    public class ImportGherkinFeatureWizard : WizardBase 
    {
        // shared data across pages goes here        

        public string Folder { get; internal set; }
        public string mFolder;
        public bool Imported;
        public string mFeatureFile;
        public BusinessFlow BizFlow;
        public GenericWindow genWin;
        public eImportGherkinFileContext mContext;
        public string FetaureFileName;
        ImportGherkinTargetFolder importGherkinTargetFolder;

        public ImportGherkinFeatureWizard(string folder, eImportGherkinFileContext context)
        {
            Folder = folder;
            mContext = context;
            importGherkinTargetFolder = new ImportGherkinTargetFolder(mContext);

            AddPage(Name: "Intro", Title: "Import Gherkin Intro", SubTitle: "Importing BDD Gherkin File...", Page: new ImportGherkinIntroPage());

            if (mContext == eImportGherkinFileContext.BusinessFlowFolder)
            {
                AddPage(Name: "SelectDocumentsFolder", Title: "Target Feature File Path", SubTitle: "Select Feature Folder...", Page: importGherkinTargetFolder);
            }

            AddPage(Name: "SelectFile", Title: "Select Feature File", SubTitle: "Choose ...", Page: new ImportGherkinFeatureFilePage(folder, context));

            if(mContext == eImportGherkinFileContext.DocumentsFolder)
            {
                AddPage(Name: "SelectBusinessFlowFolder", Title: "Target Business Flow Path", SubTitle: "Select Target Folder...", Page: importGherkinTargetFolder);
            }

            AddPage(Name: "Summary", Title: "Summary", SubTitle: "here is what will happen when you click finish", Page: new ImportGherkinFeatureSummaryPage());
        }

        public override string Title { get { return "Import Gherkin Feature Wizard"; } }

        public override void Finish()
        {
            if (Import() == "")
            {
                FetaureFileName = "";
                return;
            }               

            Imported = true;
            if (!string.IsNullOrEmpty(mFeatureFile))
            {
                GherkinPage GP = new GherkinPage();
                //GP = importGherkinTargetFolder.mTargetPath + mFeatureFile;
                bool Compiled = GP.Load(mFeatureFile);                
                //GP.Optimize();
                if (Compiled)
                {
                    string BFName = System.IO.Path.GetFileName(mFeatureFile).Replace(".feature", "");
                    GP.CreateNewBF(BFName, mFeatureFile);
                    GP.CreateActivities();
                    GP.mBizFlow.Save();
                    BizFlow = GP.mBizFlow;
                }
                else
                {
                    Reporter.ToUser(eUserMsgKeys.GherkinBusinessFlowNotCreated);
                }
            }
        }

        private string Import()
        {
            if (String.IsNullOrEmpty(mFeatureFile) || !File.Exists(mFeatureFile))
                return String.Empty;
            // Copy the feature file to local docs
            //string FeatureFolder = App.UserProfile.Solution.ContainingFolderFullPath + @"\Documents\";

            //if (mFolder != "Business Flows" && mContext == eImportGherkinFileContext.BusinessFlowFolder)
            //    FeatureFolder = FeatureFolder + mFolder + "\\";
            //else if (mFolder != "Documents" && mFolder != "Features" && mContext == eImportGherkinFileContext.DocumentsFolder)
            //    FeatureFolder = FeatureFolder + mFolder + "\\";

            //if (!Directory.Exists(FeatureFolder))
            //{
            //    Directory.CreateDirectory(FeatureFolder);
            //}

            FetaureFileName = System.IO.Path.GetFileName(mFeatureFile);
            string targetFile = Path.Combine(Folder, FetaureFileName);
            

            if (targetFile == mFeatureFile)
            {                
                Reporter.ToUser(eUserMsgKeys.GherkinNotifyFeatureFileSelectedFromTheSolution, targetFile);
                return String.Empty;
            }

            // TODO: make the check earlier in wizard !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Remove
            if (File.Exists(targetFile))
            {                
                Reporter.ToUser(eUserMsgKeys.GherkinNotifyFeatureFileExists, targetFile);
                return String.Empty;
            }
            File.Copy(mFeatureFile, targetFile);
            Reporter.ToUser(eUserMsgKeys.GherkinFeatureFileImportedSuccessfully, targetFile);
            

            return targetFile;
        }
    }
}
