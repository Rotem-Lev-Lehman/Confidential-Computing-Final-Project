"""
vectorize.py
============
משימה 2: הפיכת ה-DB המקומי של בית חולים לוקטור היסטוגרמה באורך קבוע M.

כל בית חולים ממפה את הרשומות המקומיות שלו לוקטור באורך M = len(regions).
V[j] = מספר החולים החיוביים ב-regions[j] אצל בית החולים הזה.

** למה זה קריטי: ** ה-mapping של index -> region נגזר מרשימת regions
בקונפיג, שזהה בכל 4 הצמתים. זה מה שהופך את ה-Secure Sum למשמעותי --
כל צומת מסכים ש-index j מייצג את אותו region בדיוק. אם צומת אחד יבנה
mapping שונה, נסכם תפוחים עם תפוזים והתוצאה תהיה שגויה בשקט.
"""

from typing import Iterable


class UnknownRegionError(ValueError):
    """
    נזרקת כשרשומה מפנה ל-region שלא קיים בקונפיג.

    אנחנו נכשלים מהר (fail-fast) ולא בולעים את הרשומה בשקט: בליעה שקטה
    של נתוני בריאות תשבש את הסכום הגלובלי בלי שום עקבות -- מישהו יראה
    תוצאה שגויה בלי לדעת שאיבד רשומות. שגיאה מפורשת מכריחה לתקן את
    המקור (data מלוכלך או config לא מסונכרן).
    """


def build_region_index(regions: list[str]) -> dict[str, int]:
    """
    בונה lookup של region -> index מתוך הרשימה הסדורה בקונפיג.

    בונים dict פעם אחת ומשתמשים בו שוב, כדי שהוקטוריזציה תהיה O(N) על
    מספר הרשומות במקום O(N*M) (חיפוש לינארי ברשימה לכל רשומה).

    TODO 1: החזר dict שממפה כל region לאינדקס שלו.
            רמז: enumerate(regions) נותן זוגות (idx, region).
            {region: idx for idx, region in enumerate(regions)}
    """
    pass  # TODO 1


def vectorize(records: Iterable[str], regions: list[str], p: int) -> list[int]:
    """
    ממיר iterable של תוויות region (אחת לכל חולה חיובי) לוקטור
    ההיסטוגרמה V באורך M, מצומצם mod p.

    Args:
        records: iterable של תוויות region -- אחת לכל חולה חיובי.
                 (כל איבר הוא ה-region של חולה בודד.)
        regions: רשימת ה-regions הציבורית והסדורה מהקונפיג (אורך M).
        p:       המודולוס הראשוני הציבורי.

    Returns:
        V: list[int] באורך M, כאשר V[j] = (ספירה מקומית ל-regions[j]) % p.

    Raises:
        UnknownRegionError: אם רשומה מפנה ל-region שלא קיים ב-regions.

    -------------------------------------------------------------------
    TODO 2: בנה את ה-lookup:   region_to_idx = build_region_index(regions)
    TODO 3: אתחל את הוקטור:     M = len(regions); V = [0] * M
    TODO 4: עבור על records. לכל record:
              idx = region_to_idx.get(record)
              - מקרה קצה: אם idx is None  ->  raise UnknownRegionError(...)
                (record לא מוכר -- אל תבלע אותו)
              - אחרת: V[idx] += 1
    TODO 5: מקרה קצה / אינווריאנט: צמצם כל איבר mod p לפני ההחזרה.
              V = [count % p for count in V]
              זה זול, אידמפוטנטי, ומבטיח שכל איבר ב-[0, p) בכניסה
              ל-split_into_shares. חשוב במיוחד לקראת share reduction
              בהמשך, שם עובדים עם ערכים אקראיים מלאים ב-[0, p).
    -------------------------------------------------------------------
    """
    pass  # TODO 2-5


if __name__ == "__main__":
    # smoke test ידני -- הרץ אותי אחרי שתמלא את ה-TODOs
    regions = ["72701", "72703", "72704"]
    records = ["72701", "72701", "72703"]
    v = vectorize(records, regions, p=1048573)
    print("vector:", v)                 # מצופה: [2, 1, 0]
    assert v == [2, 1, 0], f"got {v}"
    print("smoke test passed")
