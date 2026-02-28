from typing import Dict, Any

class NakshatraMatcher:
    def __init__(self):
        # Define nakshatra compatibility rules (score 1-3, higher is better)
        self.compatibility_rules = {
            "Ashwini": {
                "Bharani": 3, "Krittika": 2, "Rohini": 1,
                "Mrigashira": 2, "Ardra": 1, "Punarvasu": 3
            },
            "Bharani": {
                "Krittika": 3, "Rohini": 2, "Mrigashira": 1,
                "Ardra": 2, "Punarvasu": 3, "Pushya": 1
            },
            "Krittika": {
                "Rohini": 3, "Mrigashira": 2, "Ardra": 1,
                "Punarvasu": 2, "Pushya": 3, "Ashlesha": 1
            },
            "Rohini": {
                "Mrigashira": 3, "Ardra": 2, "Punarvasu": 1,
                "Pushya": 2, "Ashlesha": 3, "Magha": 1
            },
            "Mrigashira": {
                "Ardra": 3, "Punarvasu": 2, "Pushya": 1,
                "Ashlesha": 2, "Magha": 3, "PurvaPhalguni": 1
            },
            "Ardra": {
                "Punarvasu": 3, "Pushya": 2, "Ashlesha": 1,
                "Magha": 2, "PurvaPhalguni": 3, "UttaraPhalguni": 1
            },
            "Punarvasu": {
                "Pushya": 3, "Ashlesha": 2, "Magha": 1,
                "PurvaPhalguni": 2, "UttaraPhalguni": 3, "Hasta": 1
            },
            "Pushya": {
                "Ashlesha": 3, "Magha": 2, "PurvaPhalguni": 1,
                "UttaraPhalguni": 2, "Hasta": 3, "Chitra": 1
            },
            "Ashlesha": {
                "Magha": 3, "PurvaPhalguni": 2, "UttaraPhalguni": 1,
                "Hasta": 2, "Chitra": 3, "Swati": 1
            },
            "Magha": {
                "PurvaPhalguni": 3, "UttaraPhalguni": 2, "Hasta": 1,
                "Chitra": 2, "Swati": 3, "Vishakha": 1
            },
            "PurvaPhalguni": {
                "UttaraPhalguni": 3, "Hasta": 2, "Chitra": 1,
                "Swati": 2, "Vishakha": 3, "Anuradha": 1
            },
            "UttaraPhalguni": {
                "Hasta": 3, "Chitra": 2, "Swati": 1,
                "Vishakha": 2, "Anuradha": 3, "Jyeshtha": 1
            },
            "Hasta": {
                "Chitra": 3, "Swati": 2, "Vishakha": 1,
                "Anuradha": 2, "Jyeshtha": 3, "Moola": 1
            },
            "Chitra": {
                "Swati": 3, "Vishakha": 2, "Anuradha": 1,
                "Jyeshtha": 2, "Moola": 3, "Purvashada": 1
            },
            "Swati": {
                "Vishakha": 3, "Anuradha": 2, "Jyeshtha": 1,
                "Moola": 2, "Purvashada": 3, "Uttarashada": 1
            },
            "Vishakha": {
                "Anuradha": 3, "Jyeshtha": 2, "Moola": 1,
                "Purvashada": 2, "Uttarashada": 3, "Shravana": 1
            },
            "Anuradha": {
                "Jyeshtha": 3, "Moola": 2, "Purvashada": 1,
                "Uttarashada": 2, "Shravana": 3, "Dhanishta": 1
            },
            "Jyeshtha": {
                "Moola": 3, "Purvashada": 2, "Uttarashada": 1,
                "Shravana": 2, "Dhanishta": 3, "Shatabhisha": 1
            },
            "Moola": {
                "Purvashada": 3, "Uttarashada": 2, "Shravana": 1,
                "Dhanishta": 2, "Shatabhisha": 3, "Purvabhadra": 1
            },
            "Purvashada": {
                "Uttarashada": 3, "Shravana": 2, "Dhanishta": 1,
                "Shatabhisha": 2, "Purvabhadra": 3, "Uttarabhadra": 1
            },
            "Uttarashada": {
                "Shravana": 3, "Dhanishta": 2, "Shatabhisha": 1,
                "Purvabhadra": 2, "Uttarabhadra": 3, "Revati": 1
            },
            "Shravana": {
                "Dhanishta": 3, "Shatabhisha": 2, "Purvabhadra": 1,
                "Uttarabhadra": 2, "Revati": 3, "Ashwini": 1
            },
            "Dhanishta": {
                "Shatabhisha": 3, "Purvabhadra": 2, "Uttarabhadra": 1,
                "Revati": 2, "Ashwini": 3, "Bharani": 1
            },
            "Shatabhisha": {
                "Purvabhadra": 3, "Uttarabhadra": 2, "Revati": 1,
                "Ashwini": 2, "Bharani": 3, "Krittika": 1
            },
            "Purvabhadra": {
                "Uttarabhadra": 3, "Revati": 2, "Ashwini": 1,
                "Bharani": 2, "Krittika": 3, "Rohini": 1
            },
            "Uttarabhadra": {
                "Revati": 3, "Ashwini": 2, "Bharani": 1,
                "Krittika": 2, "Rohini": 3, "Mrigashira": 1
            },
            "Revati": {
                "Ashwini": 3, "Bharani": 2, "Krittika": 1,
                "Rohini": 2, "Mrigashira": 3, "Ardra": 1
            }
        }
        
        # Define utthamam (excellent) matches - most compatible pairs
        self.utthamam_matches = {
            "Ashwini": ["Bharani", "Punarvasu", "Dhanishta"],
            "Bharani": ["Krittika", "Pushya", "Shatabhisha"],
            "Krittika": ["Rohini", "Ashlesha", "Purvabhadra"],
            "Rohini": ["Mrigashira", "Magha", "Uttarabhadra"],
            "Mrigashira": ["Ardra", "PurvaPhalguni", "Revati"],
            "Ardra": ["Punarvasu", "UttaraPhalguni", "Ashwini"],
            "Punarvasu": ["Pushya", "Hasta", "Bharani"],
            "Pushya": ["Ashlesha", "Chitra", "Krittika"],
            "Ashlesha": ["Magha", "Swati", "Rohini"],
            "Magha": ["PurvaPhalguni", "Vishakha", "Mrigashira"],
            "PurvaPhalguni": ["UttaraPhalguni", "Anuradha", "Ardra"],
            "UttaraPhalguni": ["Hasta", "Jyeshtha", "Punarvasu"],
            "Hasta": ["Chitra", "Moola", "Pushya"],
            "Chitra": ["Swati", "Purvashada", "Ashlesha"],
            "Swati": ["Vishakha", "Uttarashada", "Magha"],
            "Vishakha": ["Anuradha", "Shravana", "PurvaPhalguni"],
            "Anuradha": ["Jyeshtha", "Dhanishta", "UttaraPhalguni"],
            "Jyeshtha": ["Moola", "Shatabhisha", "Hasta"],
            "Moola": ["Purvashada", "Purvabhadra", "Chitra"],
            "Purvashada": ["Uttarashada", "Uttarabhadra", "Swati"],
            "Uttarashada": ["Shravana", "Revati", "Vishakha"],
            "Shravana": ["Dhanishta", "Ashwini", "Anuradha"],
            "Dhanishta": ["Shatabhisha", "Bharani", "Jyeshtha"],
            "Shatabhisha": ["Purvabhadra", "Krittika", "Moola"],
            "Purvabhadra": ["Uttarabhadra", "Rohini", "Purvashada"],
            "Uttarabhadra": ["Revati", "Mrigashira", "Uttarashada"],
            "Revati": ["Ashwini", "Ardra", "Shravana"]
        }
        
        # Define madhyamam (good) matches - secondary compatible pairs
        self.madhyamam_matches = {
            "Ashwini": ["Krittika", "Rohini", "Revati"],
            "Bharani": ["Rohini", "Mrigashira", "Purvabhadra"],
            "Krittika": ["Mrigashira", "Ardra", "Uttarabhadra"],
            "Rohini": ["Ardra", "Punarvasu", "Revati"],
            "Mrigashira": ["Punarvasu", "Pushya", "Ashwini"],
            "Ardra": ["Pushya", "Ashlesha", "Bharani"],
            "Punarvasu": ["Ashlesha", "Magha", "Krittika"],
            "Pushya": ["Magha", "PurvaPhalguni", "Rohini"],
            "Ashlesha": ["PurvaPhalguni", "UttaraPhalguni", "Mrigashira"],
            "Magha": ["UttaraPhalguni", "Hasta", "Ardra"],
            "PurvaPhalguni": ["Hasta", "Chitra", "Punarvasu"],
            "UttaraPhalguni": ["Chitra", "Swati", "Pushya"],
            "Hasta": ["Swati", "Vishakha", "Ashlesha"],
            "Chitra": ["Vishakha", "Anuradha", "Magha"],
            "Swati": ["Anuradha", "Jyeshtha", "PurvaPhalguni"],
            "Vishakha": ["Jyeshtha", "Moola", "UttaraPhalguni"],
            "Anuradha": ["Moola", "Purvashada", "Hasta"],
            "Jyeshtha": ["Purvashada", "Uttarashada", "Chitra"],
            "Moola": ["Uttarashada", "Shravana", "Swati"],
            "Purvashada": ["Shravana", "Dhanishta", "Vishakha"],
            "Uttarashada": ["Dhanishta", "Shatabhisha", "Anuradha"],
            "Shravana": ["Shatabhisha", "Purvabhadra", "Jyeshtha"],
            "Dhanishta": ["Purvabhadra", "Uttarabhadra", "Moola"],
            "Shatabhisha": ["Uttarabhadra", "Revati", "Purvashada"],
            "Purvabhadra": ["Revati", "Ashwini", "Uttarashada"],
            "Uttarabhadra": ["Ashwini", "Bharani", "Shravana"],
            "Revati": ["Bharani", "Krittika", "Dhanishta"]
        }

    def check_compatibility(self, Male_nakshatra: str, Female_nakshatra: str) -> Dict[str, Any]:
        Male_nakshatra = Male_nakshatra.strip().capitalize()
        Female_nakshatra = Female_nakshatra.strip().capitalize()
        
        # Check for utthamam match
        is_utthamam = Female_nakshatra in self.utthamam_matches.get(Male_nakshatra, [])
        
        # Check for madhyamam match if not utthamam
        is_madhyamam = False
        if not is_utthamam:
            is_madhyamam = Female_nakshatra in self.madhyamam_matches.get(Male_nakshatra, [])
        
        # Calculate combined score
        score = self.compatibility_rules.get(Male_nakshatra, {}).get(Female_nakshatra, 0)
        
        return {
            "is_utthamam": is_utthamam,
            "is_madhyamam": is_madhyamam,
            "combined_score": score,
            "Male_nakshatra": Male_nakshatra,
            "Female_nakshatra": Female_nakshatra
        }

nakshatra_matcher = NakshatraMatcher()
