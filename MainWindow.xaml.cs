using System;
using System.Numerics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace RSA
{
    public partial class MainWindow : Window
    {
        private RSAAlgorithm rsa = new RSAAlgorithm();
        private int currentBitSize = 128; // Значение по умолчанию
        private Random random = new Random();
        private bool isUpdating = false; // Флаг для предотвращения зацикливания
        private BigInteger lastValidSignature = 0; // Последняя корректная подпись
        private byte[] lastHash = null; // Последний вычисленный хеш
        private bool isGenerating = false; // Флаг генерации ключей

        public MainWindow()
        {
            InitializeComponent();

            // Инициализируем значения после завершения InitializeComponent
            InitializeDefaultValues();
        }

        private void InitializeDefaultValues()
        {
            try
            {
                // Устанавливаем примерные значения для демонстрации
                if (txtE != null) txtE.Text = "65537";
                if (txtMessage != null) txtMessage.Text = "Hello, RSA!";
                if (txtUserId != null) txtUserId.Text = "12345";

                // Очищаем поля p и q
                if (txtPDisplay != null) txtPDisplay.Text = string.Empty;
                if (txtQDisplay != null) txtQDisplay.Text = string.Empty;

                // Выбираем SHA-256 по умолчанию
                if (cmbHashAlgorithm != null) cmbHashAlgorithm.SelectedIndex = 1; // SHA-256

                // Синхронизируем поля при запуске
                SynchronizeTextToNumber();

                // Обновляем состояние кнопок
                UpdateButtonState();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при инициализации: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Проверка на пустое сообщение
        private bool ValidateMessage()
        {
            if (rbTextMessage.IsChecked == true)
            {
                if (string.IsNullOrWhiteSpace(txtMessage.Text))
                {
                    MessageBox.Show("Текстовое сообщение не может быть пустым", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(txtNumberMessage.Text))
                {
                    MessageBox.Show("Числовое сообщение не может быть пустым", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                if (!BigInteger.TryParse(txtNumberMessage.Text, out _))
                {
                    MessageBox.Show("Числовое сообщение должно быть корректным числом", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            return true;
        }

        // Управление отображением индикатора загрузки
        private void SetLoadingState(bool isLoading)
        {
            isGenerating = isLoading;

            // Блокируем/разблокируем элементы управления
            btnGenerateKeys.IsEnabled = !isLoading;
            cmbBitSize.IsEnabled = !isLoading;

            // Показываем/скрываем оверлей
            LoadingOverlay.Visibility = isLoading ? Visibility.Visible : Visibility.Collapsed;

            // Если показываем оверлей, запускаем анимацию текста
            if (isLoading)
            {
                StartTextAnimation();
            }

            // Обновляем состояние других кнопок
            UpdateButtonState();
        }

        // Запуск анимации текста
        private void StartTextAnimation()
        {
            try
            {
                // Находим TextBlock с анимацией
                if (LoadingText != null)
                {
                    // Принудительно запускаем анимацию, если она не запустилась автоматически
                    var storyboard = TryFindResource("AnimatedTextStyle") as Style;
                    if (storyboard != null)
                    {
                        // Анимация запустится автоматически через триггер Loaded
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка запуска анимации: {ex.Message}");
            }
        }

        // Обновление состояния кнопок шифрования
        private void UpdateButtonState()
        {
            if (btnEncryptAndSign != null && btnVerifyAndDecrypt != null)
            {
                // Кнопки шифрования доступны только если ключи сгенерированы и не идет генерация
                btnEncryptAndSign.IsEnabled = rsa.KeysGenerated && !isGenerating;
                btnVerifyAndDecrypt.IsEnabled = rsa.KeysGenerated && !isGenerating;
            }
        }

        // Проверка целостности подписи
        private void CheckSignatureIntegrity()
        {
            try
            {
                if (!rsa.KeysGenerated || string.IsNullOrWhiteSpace(txtSignature.Text) || string.IsNullOrWhiteSpace(txtCiphertext.Text))
                {
                    txtSignatureStatus.Text = string.Empty;
                    return;
                }

                BigInteger currentSignature = BigInteger.Parse(txtSignature.Text);

                if (lastValidSignature != 0 && currentSignature != lastValidSignature)
                {
                    txtSignatureStatus.Text = "⚠ Цифровая подпись была изменена!";
                    txtSignatureStatus.Foreground = System.Windows.Media.Brushes.Orange;
                }
                else if (lastValidSignature != 0 && currentSignature == lastValidSignature)
                {
                    txtSignatureStatus.Text = "✓ Цифровая подпись не изменялась";
                    txtSignatureStatus.Foreground = System.Windows.Media.Brushes.Green;
                }
            }
            catch
            {
                // Если не удалось распарсить подпись, игнорируем
                txtSignatureStatus.Text = "⚠ Неверный формат подписи";
                txtSignatureStatus.Foreground = System.Windows.Media.Brushes.Red;
            }
        }

        // Вычисление хеша на основе выбранного алгоритма
        private bool ComputeHashFromSelection(out byte[] hash, out string hashDisplay)
        {
            hash = null;
            hashDisplay = string.Empty;

            ComboBoxItem selectedItem = (ComboBoxItem)cmbHashAlgorithm.SelectedItem;
            string hashAlgorithm = selectedItem.Tag.ToString();

            if (hashAlgorithm == "USER_ID")
            {
                // Используем ID пользователя
                if (string.IsNullOrWhiteSpace(txtUserId.Text) || !int.TryParse(txtUserId.Text, out int userId))
                {
                    MessageBox.Show("Введите корректный ID пользователя (число от 1 до 1,000,000)", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                if (userId < 1 || userId > 1000000)
                {
                    MessageBox.Show("ID пользователя должен быть от 1 до 1,000,000", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                hash = HashHelper.UserIdToBytes(userId);
                hashDisplay = HashHelper.GetHashDisplay(hash, hashAlgorithm);
                return true;
            }
            else
            {
                // Проверяем, что текстовое сообщение не пустое для хеширования
                if (string.IsNullOrWhiteSpace(txtMessage.Text))
                {
                    MessageBox.Show("Текстовое сообщение не может быть пустым для вычисления хеша", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                // Используем выбранный алгоритм SHA
                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(txtMessage.Text);
                hash = HashHelper.ComputeHash(messageBytes, hashAlgorithm);
                hashDisplay = HashHelper.GetHashDisplay(hash, hashAlgorithm);
                return true;
            }
        }

        // Обработчик для полей, в которых можно вводить только цифры (без пробелов)
        private void NumberOnly_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            // Разрешаем только цифры, запрещаем любые другие символы (включая пробелы)
            foreach (char c in e.Text)
            {
                if (!char.IsDigit(c))
                {
                    e.Handled = true;
                    return;
                }
            }
        }

        // Обработчик изменения выбора битности
        private void cmbBitSize_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (cmbBitSize.SelectedItem != null)
            {
                ComboBoxItem selectedItem = (ComboBoxItem)cmbBitSize.SelectedItem;
                currentBitSize = int.Parse(selectedItem.Tag.ToString());
            }
        }

        // Обработчик изменения выбора алгоритма хэширования
        private void cmbHashAlgorithm_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (cmbHashAlgorithm.SelectedItem != null)
            {
                ComboBoxItem selectedItem = (ComboBoxItem)cmbHashAlgorithm.SelectedItem;
                string algorithm = selectedItem.Tag.ToString();

                // Включаем/отключаем поле ID в зависимости от выбора
                bool isUserIdMode = (algorithm == "USER_ID");
                if (txtUserId != null) txtUserId.IsEnabled = isUserIdMode;
                if (btnGenerateUserId != null) btnGenerateUserId.IsEnabled = isUserIdMode;
            }
        }

        // Обработчик изменения текстового поля подписи
        private void txtSignature_TextChanged(object sender, TextChangedEventArgs e)
        {
            CheckSignatureIntegrity();
        }

        // Обработчик переключения между текстовым и числовым режимами
        private void RadioButton_Checked(object sender, RoutedEventArgs e)
        {
            if (rbTextMessage.IsChecked == true)
            {
                // При переключении на текстовый режим, обновляем текст из числа
                SynchronizeNumberToText();
            }
            else
            {
                // При переключении на числовой режим, обновляем число из текста
                SynchronizeTextToNumber();
            }
        }

        // Обработчик изменения текстового поля
        private void txtMessage_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!isUpdating && rbTextMessage != null && rbTextMessage.IsChecked == true)
            {
                SynchronizeTextToNumber();
            }
        }

        // Обработчик изменения числового поля
        private void txtNumberMessage_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!isUpdating && rbNumberMessage != null && rbNumberMessage.IsChecked == true)
            {
                SynchronizeNumberToText();
            }
        }

        // Синхронизация из текста в число
        private void SynchronizeTextToNumber()
        {
            try
            {
                isUpdating = true;

                if (txtMessage == null || txtNumberMessage == null)
                    return;

                // Если текст пустой, устанавливаем число 0
                if (string.IsNullOrEmpty(txtMessage.Text))
                {
                    txtNumberMessage.Text = "0";
                    return;
                }

                BigInteger number = RSAAlgorithm.TextToBigInteger(txtMessage.Text);
                txtNumberMessage.Text = number.ToString();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка синхронизации текст->число: {ex.Message}");
            }
            finally
            {
                isUpdating = false;
            }
        }

        // Синхронизация из числа в текст
        private void SynchronizeNumberToText()
        {
            try
            {
                isUpdating = true;

                if (txtMessage == null || txtNumberMessage == null)
                    return;

                if (BigInteger.TryParse(txtNumberMessage.Text, out BigInteger number))
                {
                    // Если число равно 0, устанавливаем пустой текст
                    if (number == 0)
                    {
                        txtMessage.Text = string.Empty;
                        return;
                    }

                    string text = RSAAlgorithm.BigIntegerToText(number);

                    // Проверяем, что строка содержит только валидные символы
                    if (!string.IsNullOrEmpty(text) && RSAAlgorithm.IsValidText(text))
                    {
                        txtMessage.Text = text;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка синхронизации число->текст: {ex.Message}");
            }
            finally
            {
                isUpdating = false;
            }
        }

        // Генерация случайного ID пользователя
        private void btnGenerateUserId_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                int userId = random.Next(1, 1000001); // от 1 до 1,000,000
                txtUserId.Text = userId.ToString();
                txtStatus.Text = $"Сгенерирован ID пользователя: {userId}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при генерации ID: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Асинхронная генерация ключей с текстовой анимацией
        private async void btnGenerateKeys_Click(object sender, RoutedEventArgs _e)
        {
            // Блокируем повторный запуск
            if (isGenerating) return;

            try
            {
                // Показываем индикатор загрузки с анимированным текстом
                SetLoadingState(true);
                txtStatus.Text = $"Генерация ключей (b={currentBitSize})...";

                // Асинхронно генерируем ключи
                await Task.Run(() =>
                {
                    rsa.GenerateKeys(currentBitSize);
                });

                // Обновляем UI после завершения генерации (в главном потоке)
                await Dispatcher.InvokeAsync(() =>
                {
                    // Отображаем p и q
                    txtPDisplay.Text = rsa.P.ToString();
                    txtQDisplay.Text = rsa.Q.ToString();

                    // Отображаем ключи
                    txtPublicKey.Text = $"n = {rsa.N}\ne = {rsa.E}";
                    txtPrivateKey.Text = rsa.D.ToString();
                    txtLambda.Text = rsa.Lambda.ToString();

                    // Сбрасываем последнюю валидную подпись
                    lastValidSignature = 0;
                    lastHash = null;

                    int pBits = currentBitSize - 1;
                    int qBits = currentBitSize;
                    txtStatus.Text = $"Ключи успешно сгенерированы (p={pBits} бит, q={qBits} бит)";
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    MessageBox.Show($"Ошибка при генерации ключей: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    txtStatus.Text = "Ошибка генерации ключей";
                });
            }
            finally
            {
                // Скрываем индикатор загрузки и обновляем состояние кнопок
                await Dispatcher.InvokeAsync(() =>
                {
                    SetLoadingState(false);
                });
            }
        }

        // Шифрование и подпись
        private void btnEncryptAndSign_Click(object sender, RoutedEventArgs _e)
        {
            try
            {
                // Проверяем, что ключи сгенерированы и не идет генерация
                if (!rsa.KeysGenerated || isGenerating)
                {
                    MessageBox.Show("Сначала сгенерируйте ключи", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Проверяем, что сообщение не пустое
                if (!ValidateMessage())
                {
                    return;
                }

                txtStatus.Text = "Шифрование и создание подписи...";

                // Получаем сообщение
                BigInteger m;
                if (rbTextMessage.IsChecked == true)
                {
                    m = RSAAlgorithm.TextToBigInteger(txtMessage.Text);
                }
                else
                {
                    if (!BigInteger.TryParse(txtNumberMessage.Text, out m))
                    {
                        MessageBox.Show("Неверный формат числового сообщения", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }

                // ШИФРОВАНИЕ: используем метод Encrypt из класса RSAAlgorithm
                BigInteger c = rsa.Encrypt(m);

                // ВЫЧИСЛЕНИЕ ХЕША
                if (!ComputeHashFromSelection(out byte[] hash, out string hashDisplay))
                {
                    return;
                }

                lastHash = hash;
                BigInteger hashValue = HashHelper.HashToBigInteger(hash, rsa.N);

                // СОЗДАНИЕ ПОДПИСИ: используем метод Sign из класса RSAAlgorithm
                BigInteger signature = rsa.Sign(hashValue);

                // Сохраняем последнюю валидную подпись
                lastValidSignature = signature;

                // Отображаем результаты
                txtCiphertext.Text = c.ToString();
                txtSignature.Text = signature.ToString();
                txtHashDisplay.Text = hashDisplay;
                txtDecrypted.Text = string.Empty;
                txtSignResult.Text = string.Empty;
                txtSignatureStatus.Text = "✓ Новая подпись создана";
                txtSignatureStatus.Foreground = System.Windows.Media.Brushes.Green;

                txtStatus.Text = "Сообщение зашифровано и подписано";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                txtStatus.Text = "Ошибка";
            }
        }

        // Проверка подписи и дешифрование
        private void btnVerifyAndDecrypt_Click(object sender, RoutedEventArgs _e)
        {
            try
            {
                // Проверяем, что ключи сгенерированы и не идет генерация
                if (!rsa.KeysGenerated || isGenerating)
                {
                    MessageBox.Show("Сначала сгенерируйте ключи", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Проверяем, что сообщение не пустое
                if (!ValidateMessage())
                {
                    return;
                }

                // Получаем шифротекст и подпись
                if (string.IsNullOrWhiteSpace(txtCiphertext.Text) || string.IsNullOrWhiteSpace(txtSignature.Text))
                {
                    MessageBox.Show("Нет зашифрованного сообщения или подписи", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                txtStatus.Text = "Проверка подписи и дешифрование...";

                BigInteger c = BigInteger.Parse(txtCiphertext.Text);
                BigInteger currentSignature = BigInteger.Parse(txtSignature.Text);

                // Проверяем, не была ли изменена подпись
                if (lastValidSignature != 0 && currentSignature != lastValidSignature)
                {
                    var result = MessageBox.Show(
                        "Цифровая подпись была изменена! Вы уверены, что хотите продолжить дешифрование?",
                        "Предупреждение",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (result == MessageBoxResult.No)
                    {
                        txtStatus.Text = "Дешифрование отменено";
                        return;
                    }
                }

                // ВЫЧИСЛЕНИЕ ХЕША
                if (!ComputeHashFromSelection(out byte[] hash, out string hashDisplay))
                {
                    return;
                }

                BigInteger hashValue = HashHelper.HashToBigInteger(hash, rsa.N);

                // ПРОВЕРКА ПОДПИСИ: используем метод VerifySignature из класса RSAAlgorithm
                bool isValid = rsa.VerifySignature(hashValue, currentSignature);
                txtHashDisplay.Text = hashDisplay;

                if (isValid)
                {
                    // Подпись верна - дешифруем сообщение
                    txtSignResult.Text = "✓ Подпись действительна!";
                    txtSignResult.Foreground = System.Windows.Media.Brushes.Green;

                    // ДЕШИФРОВАНИЕ: используем метод Decrypt из класса RSAAlgorithm
                    BigInteger m = rsa.Decrypt(c);

                    try
                    {
                        string decryptedText = RSAAlgorithm.BigIntegerToText(m);

                        if (!string.IsNullOrEmpty(decryptedText))
                        {
                            txtDecrypted.Text = decryptedText;

                            // Обновляем исходное сообщение
                            if (rbTextMessage.IsChecked == true)
                            {
                                txtMessage.Text = decryptedText;
                            }
                            else
                            {
                                txtNumberMessage.Text = m.ToString();
                            }
                        }
                        else
                        {
                            txtDecrypted.Text = m.ToString();
                        }
                    }
                    catch
                    {
                        txtDecrypted.Text = m.ToString();
                    }

                    txtStatus.Text = "Подпись верна, сообщение расшифровано";
                }
                else
                {
                    // Подпись неверна - показываем ошибку
                    txtSignResult.Text = "✗ Подпись недействительна! Сообщение не может быть расшифровано.";
                    txtSignResult.Foreground = System.Windows.Media.Brushes.Red;
                    txtDecrypted.Text = "ОШИБКА: Недействительная подпись";
                    txtStatus.Text = "Ошибка проверки подписи";
                }

                // Проверяем целостность подписи после всех операций
                CheckSignatureIntegrity();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                txtStatus.Text = "Ошибка";
            }
        }
    }
}