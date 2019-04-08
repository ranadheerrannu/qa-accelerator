﻿using Amdocs.Ginger.Common.Enums;
using Amdocs.Ginger.UserControls;
using GingerCore.GeneralLib;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Ginger.UserControlsLib.UCListView
{
    /// <summary>
    /// Interaction logic for ListViewItem.xaml
    /// </summary>
    public partial class UcListViewItem : UserControl
    {
        object mItem;
        public object Item { get { return mItem; } }

        public string ItemNameField { get; set; }
        public string ItemDescriptionField { get; set; }
        public string ItemIconField { get; set; }
        public string ItemExecutionStatusField { get; set; }


        public UcListViewItem()
        {
            InitializeComponent();

            SetInitView();
        }

        private void SetInitView()
        {
            //collapse
            xExtraDetailsRow.Height = new GridLength(0);
        }

        public void ConfigItem(string itemNameField, string itemDescriptionField, string itemIconField, string itemExecutionStatusField)
        {
            ItemNameField = itemNameField;
            ItemDescriptionField = itemDescriptionField;
            ItemIconField = itemIconField;
            ItemExecutionStatusField = itemExecutionStatusField;
        }

        public void SetItem(object item)
        {
            mItem = item;
            SetItemBindings();
        }

        private void SetItemBindings()
        {
            BindingHandler.ObjFieldBinding(xItemNameTxtBlock, TextBlock.TextProperty, mItem, ItemNameField);

            if (string.IsNullOrEmpty(ItemDescriptionField))
            {
                xItemDescriptionTxtBlock.Visibility = Visibility.Collapsed;
            }
            else
            {
                BindingHandler.ObjFieldBinding(xItemDescriptionTxtBlock, TextBlock.TextProperty, mItem, ItemDescriptionField, BindingMode.OneWay);
            }

            if (!string.IsNullOrEmpty(ItemIconField))
            {
                BindingHandler.ObjFieldBinding(xItemIcon, ImageMakerControl.ImageTypeProperty, mItem, ItemIconField);
            }

            if (string.IsNullOrEmpty(ItemExecutionStatusField))
            {
                xItemIcon.Visibility = Visibility.Collapsed;
            }
            else
            {
                BindingHandler.ObjFieldBinding(xItemStatusImage, UCITemExecutionStatus.StatusProperty, mItem, ItemExecutionStatusField);
            }
        }

        

        //public static DependencyProperty ItemNameFieldProperty =
        //   DependencyProperty.Register(nameof(ItemNameField), typeof(string), typeof(UcListViewItem), new PropertyMetadata(OnItemNameFieldPropertyChanged));
        //private static void OnItemNameFieldPropertyChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
        //{
        //    var control = sender as UcListViewItem;
        //    if (control != null)
        //        control.OnActParentBusinessFlowChanged((string)args.NewValue);
        //}
        //private void OnActParentBusinessFlowChanged(string itemNameField)
        //{
        //    ItemNameField = itemNameField;
        //}
        

        private void xDetailViewBtn_Click(object sender, RoutedEventArgs e)
        {
            if (xExtraDetailsRow.ActualHeight == 0)
            {
                //expand
                xExtraDetailsRow.Height = new GridLength(25);
                xDetailViewBtn.ButtonImageType = Amdocs.Ginger.Common.Enums.eImageType.Collapse;
                xDetailViewBtn.ToolTip = "Collapse";
            }
            else
            {
                //collapse
                xExtraDetailsRow.Height = new GridLength(0);
                xDetailViewBtn.ButtonImageType = Amdocs.Ginger.Common.Enums.eImageType.Expand;
                xDetailViewBtn.ToolTip = "Expand";
            }
        }

        private void xRunnerItemContinue_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}
