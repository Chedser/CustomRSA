using System.Globalization;
using System.Windows.Controls;
using System.Windows.Data;

namespace RSA
{
    public class TagToBoolConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ComboBoxItem item)
            {
                string tag = item.Tag?.ToString();
                return tag == "USER_ID";
            }
            return false;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}