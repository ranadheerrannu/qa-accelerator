#region License
/*
Copyright © 2014-2019 European Support Limited

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

using amdocs.ginger.GingerCoreNET;
using GingerCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace Ginger.Agents
{
    public class AgentNameValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            //TODO: split to 2 rules name and unique
            if (value ==null || string.IsNullOrEmpty(value.ToString()))
            {
                return new ValidationResult(false, "Agent Name cannot be empty");
            }
            else if (IsAgentNameExist(value.ToString()))
            {
                return new ValidationResult(false, "Agent with the same name already exist");
            }
            else
            {
                return new ValidationResult(true, null);
            }        
        }

        private bool IsAgentNameExist(string value)
        {
            if ((from x in WorkSpace.Instance.SolutionRepository.GetAllRepositoryItems<Agent>() where x.Name == value select x).SingleOrDefault() != null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
    
}
