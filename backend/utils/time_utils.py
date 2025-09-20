from datetime import datetime
import pytz  # Для timezone, добавить в requirements если нужно

class TimeAndSeasonData:
    """
    Класс для вычисления текущего времени суток, сезона и timestamp.
    Учитывает timezone пользователя (Asia/Yekaterinburg, UTC+5).
    """
    def __init__(self):
        self.timezone = pytz.timezone('Asia/Yekaterinburg')
        self.now = datetime.now(self.timezone)
        self.timestamp = int(self.now.timestamp() * 1000)
        self.time_of_day = self._get_time_of_day()
        self.season = self._get_season()

    def _get_time_of_day(self) -> str:
        hour = self.now.hour
        if 6 <= hour < 12:
            return "утро"
        elif 12 <= hour < 18:
            return "день"
        elif 18 <= hour < 23:
            return "вечер"
        else:
            return "ночь"

    def _get_season(self) -> str:
        month = self.now.month
        if month in [12, 1, 2]:
            return "зима"
        elif month in [3, 4, 5]:
            return "весна"
        elif month in [6, 7, 8]:
            return "лето"
        else:
            return "осень"

    def get_time_data(self) -> dict:
        return {
            "timeOfDay": self.time_of_day,
            "season": self.season,
            "timestamp": self.timestamp,
            "currentTime": self.now.strftime("%H:%M")
        }

# Пример использования:
# time_data = TimeAndSeasonData()
# print(time_data.get_time_data())