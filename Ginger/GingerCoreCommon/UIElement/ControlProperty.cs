﻿#region License
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


using Amdocs.Ginger.Common.Enums;
using Amdocs.Ginger.Repository;
using static Amdocs.Ginger.Common.UIElement.ElementInfo;

namespace Amdocs.Ginger.Common.UIElement
{
    //TODO: rename to UIElementProperty
    public class ControlProperty : RepositoryItemBase
    {
        [IsSerializedForLocalRepository]
        public string Name { get; set; }
        [IsSerializedForLocalRepository]
        public string Value { get; set; }
        public override string ItemName { get { return Name; } set { Name = value;  } }

        public eDeltaStatus DeltaStatus { get; set; }

        public eImageType DeltaStatusIcon
        {
            get
            {
                switch (DeltaStatus)
                {
                    case ElementInfo.eDeltaStatus.Unchanged:
                        return eImageType.UnModified;
                    case ElementInfo.eDeltaStatus.Deleted:
                        return eImageType.Deleted;
                    case ElementInfo.eDeltaStatus.Modified:
                        return eImageType.Modified;
                    case ElementInfo.eDeltaStatus.New:
                        return eImageType.Added;
                    default:
                        return eImageType.UnModified;
                }
            }
        }

        public string DeltaExtraDetails { get; set; }

        public string UpdatedValue { get; set; }

        public bool IsNotEqual
        {
            get
            {
                if (DeltaStatus == eDeltaStatus.Unchanged)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }

        }
    }
}
