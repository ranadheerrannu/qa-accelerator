﻿using Amdocs.Ginger.Common;
using Amdocs.Ginger.Repository;
using Amdocs.Ginger.UserControls;
using GingerCore.GeneralLib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace Ginger.UserControlsLib.UCListView
{
    /// <summary>
    /// Interaction logic for ListViewItem.xaml
    /// </summary>
    public partial class UcListViewItem : UserControl, INotifyPropertyChanged
    {
        //public static readonly DependencyProperty ParentListProperty = DependencyProperty.Register(nameof(ParentList), typeof(UcListView), typeof(UcListViewItem), new PropertyMetadata(null, new PropertyChangedCallback(OnParentListPropertyChanged)));
        //public UcListView ParentList
        //{
        //    get
        //    {
        //        return (UcListView)GetValue(ParentListProperty);
        //    }
        //    set
        //    {
        //        SetValue(ParentListProperty, value);                                    
        //    }
        //}
        //private static void OnParentListPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        //{
        //    var control = d as UcListViewItem;
        //    if (control != null && e.NewValue != null)
        //    {
        //        control.ParentList = ((UcListView)e.NewValue);
        //    }
        //}

        public event PropertyChangedEventHandler PropertyChanged;
        public void OnPropertyChanged(string name)
        {
            PropertyChangedEventHandler handler = PropertyChanged;
            if (handler != null)
            {
                handler(this, new PropertyChangedEventArgs(name));
            }
        }

        public UcListView ParentList { get; set; }

        public bool IsSelected
        {
            get
            {
                if (ParentList != null && ParentList.CurrentItem == Item)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public static readonly DependencyProperty ItemProperty = DependencyProperty.Register(nameof(Item), typeof(object), typeof(UcListViewItem), new PropertyMetadata(null, new PropertyChangedCallback(OnItemPropertyChanged)));
        public object Item
        {
            get
            {
                return (object)GetValue(ItemProperty);
            }
            set
            {
                SetValue(ItemProperty, value);
            }
        }
        private static void OnItemPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var control = d as UcListViewItem;
            if (control != null && e.NewValue != null)
            {
                control.Item = ((object)e.NewValue);
            }
        }

        public static readonly DependencyProperty ListHelperProperty = DependencyProperty.Register(nameof(ListHelper), typeof(IListViewHelper), typeof(UcListViewItem), new PropertyMetadata(null, new PropertyChangedCallback(OnItemInfoPropertyChanged)));
        public IListViewHelper ListHelper
        {
            get
            {
                return (IListViewHelper)GetValue(ListHelperProperty);
            }
            set
            {
                SetValue(ListHelperProperty, value);
                ConfigItem();
            }
        }
        private static void OnItemInfoPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var c = d as UcListViewItem;
            if (c != null && e.NewValue != null)
            {
                c.ListHelper = ((IListViewHelper)e.NewValue);
            }
        }

        //object mItem;
        //public object Item { get { return mItem; } }

        public string ItemNameField { get; set; }
        public string ItemDescriptionField { get; set; }
        public string ItemNameExtentionField { get; set; }
        public string ItemTagsField { get; set; }
        public string ItemIconField { get; set; }
        public string ItemIconTooltipField { get; set; }
        public string ItemExecutionStatusField { get; set; }
        public string ItemActiveField { get; set; }

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

        private void ParentList_UcListViewEvent(UcListViewEventArgs EventArgs)
        {
            switch (EventArgs.EventType)
            {
                case UcListViewEventArgs.eEventType.ExpandAllItems:
                    ExpandItem();
                    break;

                case UcListViewEventArgs.eEventType.CollapseAllItems:
                    CollapseItem();
                    break;

                case UcListViewEventArgs.eEventType.UpdateIndex:
                    SetItemIndex();
                    break;
            }
        }

        //public void ConfigItem(object item, string itemNameField, string itemDescriptionField, string itemIconField, string itemExecutionStatusField="", List<ListItemNotification> notifications = null)
        //{
        //    mItem = item;

        //    ItemNameField = itemNameField;
        //    ItemDescriptionField = itemDescriptionField;
        //    ItemIconField = itemIconField;
        //    ItemExecutionStatusField = itemExecutionStatusField;
        public void ConfigItem()
        {
            ItemNameField = ListHelper.GetItemNameField();
            ItemDescriptionField = ListHelper.GetItemDescriptionField();
            ItemNameExtentionField = ListHelper.GetItemNameExtentionField();
            ItemTagsField = ListHelper.GetItemTagsField();
            ItemIconField = ListHelper.GetItemIconField();
            ItemIconTooltipField = ListHelper.GetItemIconTooltipField();
            ItemExecutionStatusField = ListHelper.GetItemExecutionStatusField();
            ItemActiveField = ListHelper.GetItemActiveField();
            this.Dispatcher.Invoke(() =>
            {
                SetItemUniqueIdentifier();
                SetItemNotifications();
                SetItemOperations();
                SetItemExtraOperations();
                SetItemExecutionOperations();
                SetItemBindings();
            });
        }

        private void SetItemUniqueIdentifier()
        {
            this.Dispatcher.Invoke(() =>
            {
                ListItemUniqueIdentifier identifier = ListHelper.GetItemUniqueIdentifier(Item);
                if (identifier != null)
                {
                    if (!String.IsNullOrEmpty(identifier.Color))
                    {
                        BrushConverter conv = new BrushConverter();
                        xIdentifierBorder.Background = conv.ConvertFromString(identifier.Color) as SolidColorBrush;
                    }
                    xIdentifierBorder.ToolTip = identifier.Tooltip;
                    xIdentifierBorder.Visibility = Visibility.Visible;
                }
                else
                {
                    xIdentifierBorder.Background = System.Windows.Media.Brushes.Transparent;
                    xIdentifierBorder.ToolTip = string.Empty;
                    xIdentifierBorder.Visibility = Visibility.Collapsed;
                }
            });
        }

        private void SetItemNotifications()
        {
            List<ListItemNotification> notifications = ListHelper.GetItemNotificationsList(Item);
            if (notifications != null)
            {
                foreach (ListItemNotification notification in notifications)
                {
                    ImageMakerControl itemInd = new ImageMakerControl();
                    itemInd.ImageType = notification.ImageType;
                    itemInd.ToolTip = notification.ToolTip;
                    itemInd.Margin = new Thickness(3, 0, 3, 0);
                    itemInd.Height = 16;
                    itemInd.Width = 16;
                    itemInd.SetAsFontImageWithSize = notification.ImageSize;

                    if (notification.ImageForeground == null)
                    {
                        itemInd.ImageForeground = System.Windows.Media.Brushes.LightPink;
                    }
                    else
                    {
                        itemInd.ImageForeground = notification.ImageForeground;
                    }

                    if (notification.BindingConverter == null)
                    {
                        BindingHandler.ObjFieldBinding(itemInd, ImageMakerControl.VisibilityProperty, notification.BindingObject, notification.BindingFieldName, BindingMode.OneWay);
                    }
                    else
                    {
                        BindingHandler.ObjFieldBinding(itemInd, ImageMakerControl.VisibilityProperty, notification.BindingObject, notification.BindingFieldName, bindingConvertor: notification.BindingConverter, BindingMode.OneWay);
                    }

                    xItemNotificationsPnl.Children.Add(itemInd);
                    xItemNotificationsClm.Width = new GridLength(xItemNotificationsClm.Width.Value + itemInd.Width + 10);
                }
            }
        }

        private void SetItemOperations()
        {
            List<ListItemOperation> operations = ListHelper.GetItemOperationsList(Item);
            if (operations != null && operations.Count > 0)
            {
                xItemOperationsPnl.Visibility = Visibility.Visible;
                foreach (ListItemOperation operation in operations)
                {
                    ucButton operationBtn = new ucButton();
                    operationBtn.ButtonType = Amdocs.Ginger.Core.eButtonType.ImageButton;
                    operationBtn.ButtonImageType = operation.ImageType;
                    operationBtn.ToolTip = operation.ToolTip;
                    operationBtn.Margin = new Thickness(-5, 0, -5, 0);
                    operationBtn.ButtonFontImageSize = operation.ImageSize;

                    if (operation.ImageForeground == null)
                    {
                        //operationBtn.ButtonImageForground = (SolidColorBrush)FindResource("$BackgroundColor_DarkBlue");
                    }
                    else
                    {
                        operationBtn.ButtonImageForground = operation.ImageForeground;
                    }

                    if (operation.ImageBindingObject != null)
                    {
                        if (operation.ImageBindingConverter == null)
                        {
                            BindingHandler.ObjFieldBinding(operationBtn, ucButton.ButtonImageTypeProperty, operation.ImageBindingObject, operation.ImageBindingFieldName, BindingMode.OneWay);
                        }
                        else
                        {
                            BindingHandler.ObjFieldBinding(operationBtn, ucButton.ButtonImageTypeProperty, operation.ImageBindingObject, operation.ImageBindingFieldName, bindingConvertor: operation.ImageBindingConverter, BindingMode.OneWay);
                        }
                    }

                    operationBtn.Click += operation.OperationHandler;
                    operationBtn.Tag = Item;

                    xItemOperationsPnl.Children.Add(operationBtn);
                }
            }
            else
            {
                xItemOperationsPnl.Visibility = Visibility.Collapsed;
            }
        }

        private void SetItemExtraOperations()
        {
            List<ListItemOperation> extraOperations = ListHelper.GetItemExtraOperationsList(Item);
            if (extraOperations != null && extraOperations.Count > 0)
            {
                xItemExtraOperationsMenu.Visibility = Visibility.Visible;
                foreach (ListItemOperation operation in extraOperations)
                {
                    MenuItem menuitem = new MenuItem();
                    menuitem.Style = (Style)FindResource("$MenuItemStyle");
                    ImageMakerControl iconImage = new ImageMakerControl();
                    iconImage.ImageType = operation.ImageType;
                    iconImage.SetAsFontImageWithSize = operation.ImageSize;
                    iconImage.HorizontalAlignment = HorizontalAlignment.Left;
                    menuitem.Icon = iconImage;
                    menuitem.Header = operation.Header;
                    menuitem.ToolTip = operation.ToolTip;

                    if (operation.ImageForeground == null)
                    {
                        //iconImage.ImageForeground = (SolidColorBrush)FindResource("$BackgroundColor_DarkBlue");
                    }
                    else
                    {
                        iconImage.ImageForeground = operation.ImageForeground;
                    }

                    if (operation.ImageBindingObject != null)
                    {
                        if (operation.ImageBindingConverter == null)
                        {
                            BindingHandler.ObjFieldBinding(iconImage, ImageMaker.ContentProperty, operation.ImageBindingObject, operation.ImageBindingFieldName, BindingMode.OneWay);
                        }
                        else
                        {
                            BindingHandler.ObjFieldBinding(iconImage, ImageMaker.ContentProperty, operation.ImageBindingObject, operation.ImageBindingFieldName, bindingConvertor: operation.ImageBindingConverter, BindingMode.OneWay);
                        }
                    }

                    menuitem.Click += operation.OperationHandler;

                    menuitem.Tag = Item;

                    ((MenuItem)(xItemExtraOperationsMenu.Items[0])).Items.Add(menuitem);
                }
            }
            else
            {
                xItemExtraOperationsMenu.Visibility = Visibility.Collapsed;
            }
        }

        private void SetItemExecutionOperations()
        {
            List<ListItemOperation> executionOperations = ListHelper.GetItemExecutionOperationsList(Item);
            if (executionOperations != null && executionOperations.Count > 0)
            {
                xOperationsSplitter.Visibility = Visibility.Visible;
                xItemExecutionOperationsPnl.Visibility = Visibility.Visible;
                foreach (ListItemOperation operation in executionOperations)
                {
                    ucButton operationBtn = new ucButton();                   
                    operationBtn.ButtonType = Amdocs.Ginger.Core.eButtonType.ImageButton;
                    operationBtn.ButtonImageType = operation.ImageType;
                    operationBtn.ToolTip = operation.ToolTip;
                    operationBtn.Margin = new Thickness(-5, 0, -5, 0);
                    operationBtn.ButtonImageHeight = 15;
                    operationBtn.ButtonImageWidth = 15;
                    operationBtn.ButtonFontImageSize = operation.ImageSize;
                    operationBtn.ButtonStyle = (Style)FindResource("$ImageButtonStyle_Execution");

                    if (operation.ImageForeground == null)
                    {
                        //operationBtn.ButtonImageForground = (SolidColorBrush)FindResource("$BackgroundColor_DarkBlue");
                    }
                    else
                    {
                        operationBtn.ButtonImageForground = operation.ImageForeground;
                    }

                    if (operation.ImageBindingObject != null)
                    {
                        if (operation.ImageBindingConverter == null)
                        {
                            BindingHandler.ObjFieldBinding(operationBtn, ucButton.ButtonImageTypeProperty, operation.ImageBindingObject, operation.ImageBindingFieldName, BindingMode.OneWay);
                        }
                        else
                        {
                            BindingHandler.ObjFieldBinding(operationBtn, ucButton.ButtonImageTypeProperty, operation.ImageBindingObject, operation.ImageBindingFieldName, bindingConvertor: operation.ImageBindingConverter, BindingMode.OneWay);
                        }
                    }

                    operationBtn.Click += operation.OperationHandler;
                    operationBtn.Tag = Item;

                    xItemExecutionOperationsPnl.Children.Add(operationBtn);
                }
            }
            else
            {
                xOperationsSplitter.Visibility = Visibility.Collapsed;
                xItemExecutionOperationsPnl.Visibility = Visibility.Collapsed;
            }
        }

        private void SetItemBindings()
        {
            if (Item is RepositoryItemBase)
            {
                ((RepositoryItemBase)Item).PropertyChanged -= Item_PropertyChanged;
                ((RepositoryItemBase)Item).PropertyChanged += Item_PropertyChanged;
            }
            SetItemFullName();

            SetItemDescription();

            if (!string.IsNullOrEmpty(ItemIconField))
            {
                BindingHandler.ObjFieldBinding(xItemIcon, ImageMakerControl.ImageTypeProperty, Item, ItemIconField, BindingMode:BindingMode.OneWay);
            }
            if (!string.IsNullOrEmpty(ItemIconTooltipField))
            {
                BindingHandler.ObjFieldBinding(xItemIcon, ImageMakerControl.ImageToolTipProperty, Item, ItemIconTooltipField, BindingMode: BindingMode.OneWay);
            }

            if (!string.IsNullOrEmpty(ItemActiveField))
            {
                System.Windows.Data.Binding b = new System.Windows.Data.Binding();
                b.Source = Item;
                b.Path = new PropertyPath(ItemActiveField);
                b.Mode = BindingMode.OneWay;
                b.Converter = new ActiveBackgroundColorConverter();
                b.UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged;
                xListItemGrid.SetBinding(Grid.BackgroundProperty, b);
            }

            if (string.IsNullOrEmpty(ItemExecutionStatusField))
            {
                xItemStatusImage.Visibility = Visibility.Collapsed;
                xItemStatusClm.Width = new GridLength(0);
            }
            else
            {
                BindingHandler.ObjFieldBinding(xItemStatusImage, UcItemExecutionStatus.StatusProperty, Item, ItemExecutionStatusField);
                xItemStatusClm.Width = new GridLength(25);
            }
        }

        private void Item_PropertyChanged(object sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == ItemNameField || e.PropertyName == ItemNameExtentionField)
            {
                SetItemFullName();
            }
            else if (e.PropertyName == ItemDescriptionField || e.PropertyName == ItemTagsField)
            {
                SetItemDescription();
            }
            SetItemUniqueIdentifier();            
        }

        private void xExpandCollapseBtn_Click(object sender, RoutedEventArgs e)
        {
            if (xExtraDetailsRow.ActualHeight == 0)
            {
                //expand
                ExpandItem();
            }
            else
            {
                //collapse
                CollapseItem();
            }
        }

        public void ExpandItem()
        {
            xExtraDetailsRow.Height = new GridLength(25);
            xExpandCollapseBtn.ButtonImageType = Amdocs.Ginger.Common.Enums.eImageType.Collapse;
            xExpandCollapseBtn.ToolTip = "Collapse";
        }

        public void CollapseItem()
        {
            xExtraDetailsRow.Height = new GridLength(0);
            xExpandCollapseBtn.ButtonImageType = Amdocs.Ginger.Common.Enums.eImageType.Expand;
            xExpandCollapseBtn.ToolTip = "Expand";
        }

        private void UcListViewItem_Loaded(object sender, RoutedEventArgs e)
        {
            if (ParentList == null)
            {
                var parent = GingerCore.General.TryFindParent<UcListView>(this);
                if (parent != null)
                {
                    ParentList = (UcListView)parent;
                    ParentList.UcListViewEvent -= ParentList_UcListViewEvent;
                    ParentList.UcListViewEvent += ParentList_UcListViewEvent;
                    ParentList.List.SelectionChanged -= ParentList_SelectionChanged;
                    ParentList.List.SelectionChanged += ParentList_SelectionChanged;
                }
                OnPropertyChanged(nameof(IsSelected));
            }
            SetItemIndex();
        }

        private void ParentList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            OnPropertyChanged(nameof(IsSelected));
        }

        private void SetItemIndex()
        {
            if (ParentList != null)
            {
                //xItemIndexTxt.Text = (ParentList.List.ItemContainerGenerator.IndexFromContainer(this) + 1).ToString();
                xItemIndexTxt.Text = (ParentList.List.Items.IndexOf(Item) + 1).ToString();
            }
        }

        private void SetItemFullName()
        {
            try
            {
                xItemNameTxtBlock.Text = string.Empty;
                string fullname = string.Empty;
                if (!string.IsNullOrEmpty(ItemNameField))
                {
                    Object name = Item.GetType().GetProperty(ItemNameField).GetValue(Item);
                    if (name != null)
                    {                        
                        xItemNameTxtBlock.Inlines.Add(new System.Windows.Documents.Run
                        {
                            FontSize = 15,
                            Text = name.ToString() + " "
                        });

                        fullname += name;
                    }
                }
                if (!string.IsNullOrEmpty(ItemNameExtentionField))
                {
                    Object group = Item.GetType().GetProperty(ItemNameExtentionField).GetValue(Item);
                    if (group != null)
                    {
                        xItemNameTxtBlock.Inlines.Add(new System.Windows.Documents.Run
                        {
                            FontSize = 10,
                            Text = string.Format("[{0}]", group.ToString())
                        });

                        fullname += string.Format("[{0}]", group.ToString());
                    }
                }

                xItemNameTxtBlock.ToolTip = fullname;
            }
            catch (Exception ex)
            {
                xItemDescriptionTxtBlock.Text = "Failed to set Name!;";
                Reporter.ToLog(eLogLevel.ERROR, "Failed to set ListViewItem Name", ex);
            }
        }

        private void SetItemDescription()
        {
            try
            {
                string fullDesc = string.Empty;
                if (!string.IsNullOrEmpty(ItemDescriptionField))
                {
                    Object desc = Item.GetType().GetProperty(ItemDescriptionField).GetValue(Item);
                    if (desc != null)
                    {
                        fullDesc += desc.ToString() + " ";
                    }
                }

                if (!string.IsNullOrEmpty(ItemTagsField))
                {
                    Object tags = Item.GetType().GetField(ItemTagsField).GetValue(Item);
                    fullDesc += General.GetTagsListAsString((ObservableList<Guid>)tags) + " ";                    
                }

                xItemDescriptionTxtBlock.Text = fullDesc;
                xItemDescriptionTxtBlock.ToolTip = fullDesc;
            }
            catch(Exception ex)
            {
                xItemDescriptionTxtBlock.Text = "Failed to set description!;";
                Reporter.ToLog(eLogLevel.ERROR, "Failed to set ListViewItem Description", ex);
            }
        }
    }

    public class ActiveBackgroundColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value != null && value is bool && ((bool)value) == false)
            {
                return System.Windows.Media.Brushes.LightGray;
            }
            else
            {
                return System.Windows.Media.Brushes.White;
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
