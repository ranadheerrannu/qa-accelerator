﻿using Amdocs.Ginger.CoreNET.Drivers.CommunicationProtocol;
using Amdocs.Ginger.CoreNET.Run;
using Ginger.Plugin.Platform.Web;
using Ginger.Plugin.Platform.Web.Elements;
using GingerCore;
using GingerCore.Actions;
using GingerCore.Actions.Common;
using GingerCoreNET.DriversLib;
using GingerCoreNET.RunLib;
using GingerPluginCoreTest.CommunicationProtocol.WebPlatformServiceFakeLib;
using GingerTestHelper;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GingerPluginCoreTest.CommunicationProtocol
{

    // this tests are for checking plugin action pack to payload send via GingerNodeProxy, execute on GingerNode and service then getting response

    [TestClass]
    [Level2]
    public class GingerGridCommTest
    {
        static GingerGrid gingerGrid;
        static GingerNode gingerNode;
        static IWebPlatform webPlatform;
        static GingerNodeProxy gingerNodeProxy;
        static Agent agent;

        [ClassInitialize()]
        public static void ClassInit(TestContext context)
        {
            int port = SocketHelper.GetOpenPort();

            // gingerGrid = WorkSpace.Instance.LocalGingerGrid; // new GingerGrid(port); 
            gingerGrid = new GingerGrid(port);
            gingerGrid.Start();

            // WorkSpace.Instance.LocalGingerGrid = gingerGrid;

            webPlatform = new WebPlatformServiceFake();
            gingerNode = new GingerNode(webPlatform);
            gingerNode.StartGingerNode("WebPlatformServiceFake 1", SocketHelper.GetLocalHostIP(), port);

            // Wait for node to be connected.

            gingerNodeProxy = new GingerNodeProxy(gingerGrid.NodeList[0]);
            gingerNodeProxy.GingerGrid = gingerGrid;

            // GingerRunner gingerRunner = new GingerRunner();
            agent = new Agent();
            agent.GingerNodeProxy = gingerNodeProxy;
            agent.Platform = GingerCoreNET.SolutionRepositoryLib.RepositoryObjectsLib.PlatformsLib.ePlatformType.Service;
            // agent.PluginId = "aa";
            agent.ServiceId = "WebPlatformServiceFake";
            agent.AgentType = Agent.eAgentType.Service;
            agent.DriverConfiguration = new Amdocs.Ginger.Common.ObservableList<DriverConfigParam>();

            //agent.st
            // agent.StartDriver();
            gingerNodeProxy.StartDriver(agent.DriverConfiguration);

        }


        [ClassCleanup()]
        public static void ClassCleanup()
        {
            // gingerGrid.shutdown...

        }

        [TestMethod]
        public void SpeedTest()
        {
            for (int i = 0; i < 10000;i++)
            {
                // SetTextBoxText();
                 // ClickButtonGrid();
                 // ClickButtonNotExist();
                  GotoURLGrid();
                 // GotoURLDirect();
            }
        }

        [TestMethod]
        public void GotoURLDirect()
        {
            // Arrange
            string url = "http://www.google.com";

            // Act
            webPlatform.BrowserActions.Navigate(url, "???");
            string browserurl = webPlatform.BrowserActions.GetCurrentUrl();

            //Assert
            Assert.AreEqual(url, browserurl, "URL of naviagte equel browser url");
        }


        [TestMethod]
        public void GotoURLGrid()
        {
            //Arrange
            string url = "aaa";

            ActBrowserElement actBrowserElement = new ActBrowserElement();
            actBrowserElement.ControlAction = ActBrowserElement.eControlAction.GotoURL;
            actBrowserElement.Value = url;               

            //Act            
            ExecuteOnPlugin.ExecutePlugInActionOnAgent(agent, actBrowserElement);

            //Assert            
            Assert.IsTrue(string.IsNullOrEmpty(actBrowserElement.Error), "No Error");            
            Assert.AreEqual("Navigated to: " + url, actBrowserElement.ExInfo, "ExInfo");            
            Assert.AreEqual(1, actBrowserElement.ReturnValues.Count, "actBrowserElement.ReturnValues.Count");
        }

        [Ignore] // Failing need GR + VE, Create test with GR
        [TestMethod]
        public void GotoURLGridWithValueExpression()
        {
            //Arrange
            string VEURL = "{CS Exp=@\"badurl\".Replace(@\"bad\",@\"good\")}";
            string CalculatedURL = "goodurl";

            ActBrowserElement actBrowserElement = new ActBrowserElement();
            actBrowserElement.ControlAction = ActBrowserElement.eControlAction.GotoURL;
            actBrowserElement.Value = VEURL;           

            //Act            
            ExecuteOnPlugin.ExecutePlugInActionOnAgent(agent, actBrowserElement);

            //Assert            
            Assert.IsTrue(string.IsNullOrEmpty(actBrowserElement.Error), "No Error");
            Assert.AreEqual("Navigated to: " + CalculatedURL, actBrowserElement.ExInfo, "ExInfo");
            Assert.AreEqual(0, actBrowserElement.ReturnValues.Count, "actBrowserElement.ReturnValues.Count");
        }





        [TestMethod]
        public void ClickButtonDirect()
        {
            // Arrange


            // Act
            IButton elem = (IButton)webPlatform.LocateWebElement.LocateElementByID(Ginger.Plugin.Platform.Web.Elements.eElementType.Button, "button1");
            elem.Click();
            

            //Assert
            // Assert.AreEqual(url, browserurl, "URL of naviagte equel browser url");

        }

        [TestMethod]
        public void ClickButtonGrid()
        {
            //Arrange

            ActUIElement actUIElement = new ActUIElement();
            actUIElement.ElementType = Amdocs.Ginger.Common.UIElement.eElementType.Button;
            actUIElement.ElementLocateBy = Amdocs.Ginger.Common.UIElement.eLocateBy.ByID;
            actUIElement.ElementLocateValue = "button1";
            actUIElement.ElementAction = ActUIElement.eElementAction.Click;

            //Act            
            ExecuteOnPlugin.ExecutePlugInActionOnAgent(agent, actUIElement);

            //Assert                        
            Assert.IsTrue(string.IsNullOrEmpty(actUIElement.Error), "No Error");
            Assert.AreEqual("UI Element Located using: ByID=button1", actUIElement.ExInfo, "ExInfo");
        }


        // Negative test
        [TestMethod]
        public void ClickButtonNotExist()
        {
            //Arrange

            ActUIElement actUIElement = new ActUIElement();
            actUIElement.ElementType = Amdocs.Ginger.Common.UIElement.eElementType.Button;
            actUIElement.ElementLocateBy = Amdocs.Ginger.Common.UIElement.eLocateBy.ByID;
            actUIElement.ElementLocateValue = "wrongId";
            actUIElement.ElementAction = ActUIElement.eElementAction.Click;

            //Act            
            ExecuteOnPlugin.ExecutePlugInActionOnAgent(agent, actUIElement);

            //Assert                        
            Assert.AreEqual("Element not found",actUIElement.Error, "actUIElement.Error");            
        }


        [TestMethod]
        public void SetTextBoxText()
        {
            //Arrange
            string text = "John";
            ActUIElement setTextBoxAction = new ActUIElement();
            setTextBoxAction.ElementType = Amdocs.Ginger.Common.UIElement.eElementType.TextBox;
            setTextBoxAction.ElementLocateBy = Amdocs.Ginger.Common.UIElement.eLocateBy.ByID;
            setTextBoxAction.ElementLocateValue = "user";
            setTextBoxAction.ElementAction = ActUIElement.eElementAction.SetText;
            setTextBoxAction.Value = text;

            ActUIElement getTextBoxAction = new ActUIElement();
            getTextBoxAction.ElementType = Amdocs.Ginger.Common.UIElement.eElementType.TextBox;
            getTextBoxAction.ElementLocateBy = Amdocs.Ginger.Common.UIElement.eLocateBy.ByID;
            getTextBoxAction.ElementLocateValue = "user";
            getTextBoxAction.ElementAction = ActUIElement.eElementAction.GetText;            

            //Act            
            ExecuteOnPlugin.ExecutePlugInActionOnAgent(agent, setTextBoxAction);
            ExecuteOnPlugin.ExecutePlugInActionOnAgent(agent, getTextBoxAction);
            string textBoxValue = getTextBoxAction.GetReturnParam("Actual");


            //Assert                        
            Assert.AreEqual(text, textBoxValue, "textBoxValue");
        }


    }
}