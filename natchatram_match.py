class NakshatraMatcher:
    def __init__(self):
        # Initialize the matching tables
        self.male_to_female = {}
        self.female_to_male = {}
        
        # Populate the tables with the data
        self._initialize_male_to_female_table()
        self._initialize_female_to_male_table()
    
    def _initialize_male_to_female_table(self):
        """Initialize the complete male star to female star matching table"""
        self.male_to_female = {
            'ASWINI': {
                'Rasi': 'Mesha Rasi',
                'Utthamam': (12, ['Bharani', 'Krithigai', 'Mirugaseersham', 'Punarpoosam', 'Poosam', 
                                  'Pooram', 'Uthiram', 'Chithirai', 'Visagam', 'Uthradam 2,3&4', 
                                  'Avittam', 'Poorattathi 1,2,3']),
                'Madhyamam': (7, ['Rohini', 'Thiruvadhirai', 'Anusham', 'Pooradam', 
                                 'Uthiradam 1 st Padham', 'Sadhayam', 'Avittam 3&4'])
            },
            
            'BHARANI': {
                'Rasi': 'Mesha Rasi',
                'Utthamam': (10, ['Aswini', 'Krithigai', 'Rohini', 'Thiruvadhurai', 'Magam', 
                                  'Uthiram', 'Hastham', 'Swathi', 'Uthradam 2,3,4 Padham', 'Thiruvonam']),
                'Madhyamam': (7, ['Mirugaseersham', 'Punarpoosam', 'Ayilyum', 'Chithirai', 
                                 'Visakam', 'Kettai', 'Sadhayam'])
            },
            
            'KRITHIKAI': {
                '1st Padham': {
                    'Rasi': 'Mesha Rasi',
                    'Utthamam': (10, ['Bharani', 'Rohini', 'Mirugaseersham', 'Ayilyuam', 'Pooram', 
                                     'Hastham', 'Chithirai', 'Kettai', 'Avittam', 'Revathy']),
                    'Madhyamam': (4, ['Aswini', 'Thiruvadhrai', 'Poosam', 'Magam', 'Swathi', 'Anusham'])
                },
                '2-3-4th Padhas': {
                    'Rasi': 'Rishaba Rasi',
                    'Utthamam': (10, ['Rohini', 'Mirugaseersham', 'Ayilyum', 'Pooram', 'Hastham', 
                                     'Chithirai', 'Kettai', 'Avittam 3&4', 'Revathy']),
                    'Madhyamam': (6, ['Thiruvadhirai', 'Poosam', 'Magam', 'Swathi', 'Anusham', 
                                     'Moolam', 'Uthirattadhi'])
                }
            },
            
            'ROHINI': {
                'Rasi': 'Rishaba Rasi',
                'Utthamam': (6, ['Mirugaseersham', 'Poosam', 'Uthram', 'Chithirai', 'Anusham', 'Utthirattathi']),
                'Madhyamam': (8, ['Aswini', 'Krithigai 2,3&4', 'Punarpoosam 1,2&3', 'Ayilyum', 
                                 'Visakam', 'Kettai', 'Avittam 3&4', 'Revathy'])
            },
            
            'MIRUGASEERSHAM': {
                '1&2nd Padham': {
                    'Rasi': 'Rishaba Rasi',
                    'Utthamam': (11, ['Rohini', 'Thiruvathirai', 'Punarpoosam', 'Ayilyum', 'Hastham', 
                                     'Visakam', 'Kettai', 'Thiruvonam', 'Sadhayam', 'Poorattathi', 'Revathi']),
                    'Madhyamam': (7, ['Bharani', 'Krithigai 2,3&4', 'Poosam', 'Uthiram', 'Swathi', 
                                     'Anusham', 'Uthiradam'])
                },
                '3&4th Padham': {
                    'Rasi': 'Mithuna Rasi',
                    'Utthamam': (12, ['Bharani', 'Thiruvathirai', 'Punarpoosam', 'Ayilyum', 'Hastham', 
                                     'Swathy', 'Visakam', 'Kettai', 'Pooradam', 'Thiruvonam', 
                                     'Poorattadhi 4th', 'Revathy']),
                    'Madhyamam': (9, ['Aswini', 'Krithigai 1', 'Rohini', 'Poosam', 'Uthiram', 
                                     'Anusham', 'Moolam', 'Sadhayam', 'Poorattathi 1,2&3'])
                }
            },
            
            'THIRUVADHIRAI': {
                'Rasi': 'Mithunarasi',
                'Utthamam': (13, ['Aswni', 'Krithigai 1st', 'Mirugaseersham 3&4', 'Punarpoosam', 
                                 'Poosam', 'Magam', 'Uthiram', 'Chithirai', 'Visakam', 'Moolam', 
                                 'Uthradam 1', 'Poorttathi 4', 'Uthrattathi']),
                'Madhyamam': (6, ['Bharani', 'Ayilyum', 'Pooram', 'Pooradam', 'Avittam 3&4', 
                                 'Poorattadhi 1,2,3'])
            },
            
            'PUNARPOOSAM': {
                '1,2,3': {
                    'Rasi': 'Mithuna Rasi',
                    'Utthamam': (12, ['Bharani', 'Thiruvadhirai', 'Poosam', 'Ayilyum', 'Hastham', 
                                     'Swathi', 'Anusham', 'Kettai', 'Pooradam', 'Thiruvonam', 
                                     'Uthrattathi', 'Revathy']),
                    'Madhyamam': (5, ['Aswini', 'Rohini', 'Chithirai', 'Moolam', 'Sadhayam'])
                },
                '4th Padham': {
                    'Rasi': 'Kadaka Rasi',
                    'Utthamam': (9, ['Bharani', 'Rohini', 'Poosam', 'Ayilyum', 'Hastham', 
                                     'Swathi', 'Anusham', 'Kettai', 'Thiruvonam']),
                    'Madhyamam': (6, ['Aswini', 'Chithirai', 'Moolam', 'Pooradam', 'Avittam', 
                                     'Uthirattadhi'])
                }
            },
            
            'POOSAM': {
                'Rasi': 'Kadaka Rasi',
                'Utthamam': (14, ['Aswini', 'Krithigai', 'Mirugaseersham 1&2', 'Punarpoosam', 
                                 'Ayilyum', 'Magam', 'Uthiram', 'Chithirai', 'Visakam', 'Kettai', 
                                 'Moolam', 'Uthradam', 'Avittam', 'Poorattadhi 1,2,3']),
                'Madhyamam': (4, ['Rohini', 'Hastham', 'Swathi', 'Revathy'])
            },
            
            'AYILYUM': {
                'Rasi': 'Kadaka Rasi',
                'Utthamam': (7, ['Bharani', 'Rohini', 'Poosam', 'Uthiram', 'Swathi', 'Thiruvonam', 
                                'Sadhayam']),
                'Madhyamam': (8, ['Punarpoosam 4th', 'Hastham', 'Chithirai 1&2', 'Visakam', 
                                 'Anusham', 'Uthradam', 'Avittam', 'Uthirattadhi'])
            },
            
            'MAGAM': {
                'Rasi': 'Simma Rasi',
                'Utthamam': (9, ['Krithikai 2,3 & 4', 'Pooram', 'Uthiram', 'Chithirai', 'Visakam', 
                                'Pooradam', 'Uthradam', 'Avittam', 'Poorattathi']),
                'Madhyamam': (6, ['Thiruvadhirai', 'Hastham', 'Swathi', 'Anusaham', 'Thiruvonam', 
                                 'Sadhayam'])
            },
            
            'POORAM': {
                'Rasi': 'Simma Rasi',
                'Utthamam': (7, ['Thiruvathirai', 'Uthiram', 'Hastham', 'Moolam', 'Uthradam', 
                                'Thiruvonam', 'Sadhayam']),
                'Madhyamam': (10, ['Aswini', 'Krithigai', 'Magam', 'Chithirai', 'Swathi', 
                                  'Visakam', 'Kettai', 'Avittam', 'Poorattathi 4th', 'Revathy'])
            },
            
            'UTHIRAM': {
                '1st Padham': {
                    'Rasi': 'Simma Rasi',
                    'Utthamam': (8, ['Bharani', 'Rohini', 'Mirugaseersham', 'Pooram', 'Hastham', 
                                    'Kettai', 'Pooradam', 'Avittam 3&4']),
                    'Madhyamam': (9, ['Aswini', 'Thiruvadhirai', 'Swathi', 'Anusham', 'Moolam', 
                                     'Thiruvonam', 'Avittam 1 &2', 'Sadhayam', 'Revathy'])
                },
                '2-3&4 Padham': {
                    'Rasi': 'Kanni Rasi',
                    'Utthamam': (7, ['Mirugaseersham 3&4', 'Hastham', 'Kettai', 'Pooradam', 
                                    'Thiruvonam', 'Avittam', 'Revathy']),
                    'Madhyamam': (12, ['Aswini', 'Bharani', 'Mirugaseersham 1&2', 'Thiruvadhirai', 
                                      'Poosam', 'Ayilyum', 'Pooram', 'Swathi', 'Anusham', 'Moolam', 
                                      'Sadhayam', 'Utthirattadhi'])
                }
            },
            
            'HASTHAM': {
                'Rasi': 'Kanni Rasi',
                'Utthamam': (10, ['Krithigai 1st', 'Mirugaseerusham 3&4', 'Poosam', 'Uthiram 2,3,4', 
                                 'Chithirai', 'Anusham', 'Moolam', 'Uthradam', 'Avittam', 
                                 'Utthirattathi']),
                'Madhyamam': (10, ['Krithigai 2,3&4', 'Mirugaseersham 1&2', 'Punarpoosam', 
                                  'Ayilyum', 'Magam', 'Visakam', 'Kettai', 'Pooradam', 
                                  'Poorattathi', 'Revathy'])
            },
            
            'CHITHIRAI': {
                '1&2nd Padham': {
                    'Rasi': 'Kanni Rasi',
                    'Utthamam': (13, ['Bharani', 'Thiruvadhirai', 'Punarpoosam', 'Ayilyum', 
                                     'Hastham', 'Swathi', 'Visakam', 'Kettai', 'Pooradam', 
                                     'Thiruvonam', 'Sadhayam', 'Poorattathi', 'Revathy']),
                    'Madhyamam': (6, ['Krithikai', 'Rohini', 'Poosam', 'Pooram', 'Anusham', 'Moolam'])
                },
                '3&4th Padha': {
                    'Rasi': 'Thula Rasi',
                    'Utthamam': (10, ['Bharani', 'Rohini', 'Pooram', 'Visakam', 'Anusha', 'Kettai', 
                                     'Pooradam', 'Thiruvonam', 'Sadhyam', 'Pooratathi']),
                    'Madhyamam': (9, ['Aswini', 'Krithigai', 'Thiruvadhirai', 'Punarpoosam', 
                                     'Poosam', 'Magam', 'Hastham', 'Moolam', 'Revathy'])
                }
            },
            
            'SWATHI': {
                'Rasi': 'Thula Rast',
                'Utthamam': (12, ['Krithigai', 'Mirugaseerusham', 'Punarpoosam', 'Poosam', 'Magam', 
                                 'Uthram', 'Visakam', 'Moolam', 'Uthradam', 'Avittam', 
                                 'Poorattathi', 'Uthirattadhi']),
                'Madhyamam': (6, ['Bharani', 'Pooram', 'Chithirai', 'Kettai', 'Pooradam', 'Revathy'])
            },
            
            'VISAKAM': {
                '1,2,3 Padham': {
                    'Rasi': 'Thula Rasi',
                    'Utthamam': (11, ['Bharani', 'Rohini', 'Poosam', 'Ayilyum', 'Pooram', 'Swathi', 
                                     'Anusham', 'Kettai', 'Pooradam', 'Thiruvonam', 'Revathy']),
                    'Madhyamam': (6, ['Aswini', 'Mirugaseersham 1&2', 'Chithirai 3&4', 'Moolam', 
                                     'Avitttam', 'Sadhayam'])
                },
                '4th Padham': {
                    'Rasi': 'Vrichika Rasi',
                    'Utthamam': (11, ['Rohini', 'Thiruvathirai', 'Poosam', 'Ayilyum', 'Pooram', 
                                     'Hastham', 'Anusham', 'Kettai', 'Pooradam', 'Thiruvonam', 
                                     'Sadhayam']),
                    'Madhyamam': (6, ['Aswini', 'Mirugaseersham', 'Chithirai 1&2', 'Moolam', 
                                     'Avittam', 'Revathy'])
                }
            },
            
            'ANUSHAM': {
                'Rasi': 'Vrichika Rasi',
                'Utthamam': (12, ['Aswini', 'Krithigai', 'Mirugaseersham', 'Punarpoosam', 'Magam', 
                                 'Chithirai 1&2', 'Visakam 4', 'Kettai', 'Uthradam', 'Avittam', 
                                 'Poorattathi', 'Revathy']),
                'Madhyamam': (6, ['Rohini', 'Ayilyum', 'Hastham', 'Chithirai 3&4', 
                                 'Visakam 1,2,3', 'Thiruvonam', 'Sadhayam'])
            },
            
            'KETTAI': {
                'Rasi': 'Vrichika Rasi',
                'Utthamam': (9, ['Bharani', 'Rohini', 'Pooram', 'Hastham', 'Swathi', 'Pooradam', 
                                'Thiruvonam', 'Sadhayam', 'Utthirattathi']),
                'Madhyamam': (11, ['Krithigai', 'Mirugaseersham', 'Punarpoosam 4', 'Poosam', 
                                  'Uthram', 'Chithirai 1&2', 'Visakam 4', 'Anusham', 'Uthradam', 
                                  'Avittam', 'Poorattadhi'])
            },
            
            'MOOLAM': {
                'Rasi': 'Dhanur Rasi',
                'Utthamam': (12, ['Bharani', 'Krithigai', 'Mirugaseersham', 'Punarpoosam', 'Poosam', 
                                 'Uthiram 2,3&4', 'Chithirai', 'Visakam', 'Pooradam', 'Uthradam', 
                                 'Avittam', 'Poorattathi']),
                'Madhyamam': (6, ['Thiruvadhirai', 'Pooram', 'Uthiram 1', 'Swathy', 'Thiruvonam', 
                                 'Sadhayam'])
            },
            
            'POORADAM': {
                'Rasi': 'Dhanur Rasi',
                'Utthamam': (8, ['Aswini', 'Thiruvathrai', 'Uthiram 2,3,4', 'Hastham', 'Swathi', 
                                'Uthiradam', 'Thruvonam', 'Sadhayam']),
                'Madhyamam': (7, ['Mirugaseersham 3&4', 'Punarpoosam', 'Uthiram 1', 'Moolam', 
                                 'Avittam', 'Poorattadhi', 'Revathy'])
            },
            
            'UTHRADAM': {
                '1st Padham': {
                    'Rasi': 'Dhanur Rasi',
                    'Utthamam': (8, ['Bharani', 'Rohini', 'Ayilyum', 'Hastham', 'Pooradam', 
                                    'Thiruvonam', 'Avittam', 'Revathi']),
                    'Madhyamam': (7, ['Aswini', 'Thiruvadhirai', 'Poosam', 'Pooram', 'Swathi', 
                                     'Sadhayam', 'Uthirattadhi'])
                },
                '2,3,4 Padham': {
                    'Rasi': 'Makara Rasi',
                    'Utthamam': (8, ['Bharani', 'Rohini', 'Mirugaseersham', 'Pooram', 'Thiruvonam', 
                                    'Avittam', 'Sadhayam', 'Revathy']),
                    'Madhyamam': (11, ['Aswini', 'Thiruvadhirai', 'Poosam', 'Ayilyum', 'Hastham', 
                                      'Swathi', 'Visakam', 'Anusha', 'Kettai', 'Pooradam', 
                                      'Utthirattadhi'])
                }
            },
            
            'THIRUVONAM': {
                'Rasi': 'Makara Rasi',
                'Utthamam': (8, ['Aswini', 'Mirugaseersham', 'Magam', 'Uthiram 1', 'Chithirai', 
                                'Uthradam 2,3&4', 'Avittam', 'Utthirattadhi']),
                'Madhyamam': (10, ['Bharani', 'Punarpoosam', 'Ayilyum', 'Pooram', 'Uthiram 2,3,4', 
                                  'Anusham', 'Kettai', 'Moolam', 'Poorattadhi', 'Revathy'])
            },
            
            'AVITTAM': {
                '1&2 Padham': {
                    'Rasi': 'Makara Rasi',
                    'Utthamam': (10, ['Rohini', 'Thiruvathirai', 'Punarpoosam', 'Ayilyum', 'Pooram', 
                                     'Visakam', 'Kettai', 'Thiruvonam', 'Sadhayam', 'Poorattathi 4th']),
                    'Madhyamam': (10, ['Aswini', 'Krithigai', 'Poosam', 'Magam', 'Hastham', 
                                      'Swathi', 'Pooradam', 'Uthradam 2,3 4', 'Poorattathi 4', 
                                      'Utthirattadhi'])
                },
                '3&4 Padham': {
                    'Rasi': 'Kumba Rasi',
                    'Utthamam': (11, ['Rohini', 'Thiruvathirai', 'Punarpoosam', 'Pooram', 'Hastham', 
                                     'Visakam 4', 'Kettai', 'Pooradam', 'Thiruvonam', 'Sadhayam', 
                                     'Poorattathi']),
                    'Madhyamam': (10, ['Aswini', 'Krithigai', 'Poosam', 'Ayilyum', 'Uthiram', 
                                      'Swathi', 'Visakam 1,2,3', 'Moolam', 'Uthradam', 'utthurattadhi'])
                }
            },
            
            'SADHAYAM': {
                'Rasi': 'Kumba Rasi',
                'Utthamam': (14, ['Aswini', 'Krithigai', 'Mirugaseersham', 'Punarpoosam', 'Magam', 
                                 'Pooram', 'Uthiram', 'Chithirai 1&2', 'Visakam 4', 'Moolam', 
                                 'Uthradam', 'Avittam', 'Poorattadhi', 'Utthirattadhi']),
                'Madhyamam': (7, ['Bharani', 'Poosam', 'Ayilyum', 'Chithirai 3&4', 'Visakam 1,2,3', 
                                 'Pooradam', 'Revathy'])
            },
            
            'POORATTATHI': {
                '1,2,3 Padham': {
                    'Rasi': 'Kumba Rasi',
                    'Utthamam': (9, ['Rohini', 'Thiruvadhirai', 'Pooram', 'Hastham', 'Anusham', 
                                     'Kettai', 'Pooradam', 'Thiruvonam', 'Utthirattathi']),
                    'Madhyamam': (7, ['Aswini', 'Mirugaseersham', 'Poosam', 'Ayilyum', 'Magam', 
                                     'Swathi', 'Sadhayam'])
                },
                '4th Padham': {
                    'Rasi': 'Meena Rasi',
                    'Utthamam': (9, ['Rohini', 'Thiruvadhirai', 'Poosam', 'Ayilyum', 'Pooram', 
                                    'Hastham', 'Pooradam', 'Thiruvonam', 'Utthirattathi']),
                    'Madhyamam': (4, ['Aswini', 'Mirugaseersham', 'Magam', 'Anusham'])
                }
            },
            
            'UTTHIRATTATHI': {
                'Rasi': 'Meena Rasi',
                'Utthamam': (9, ['Aswini', 'Krithigai', 'Mirugaseersham', 'Punarpoosam', 'Ayilyum', 
                                'Magam', 'Uthiram', 'Uthradam', 'Revathy']),
                'Madhyamam': (7, ['Rohini', 'Thiruvadhirai', 'Hastham', 'Moolam', 'Thiruvonam', 
                                 'Avittam', 'poorattadhi'])
            },
            
            'REVATHI': {
                'Rasi': 'Meena rasi',
                'Utthamam': (10, ['Bharani', 'Rohini', 'Thiruvathirai', 'Poosam', 'Pooram', 
                                 'Hastham', 'Swath', 'Pooradam', 'Thiruvonam', 'Utthirattathi']),
                'Madhyamam': (8, ['Krithigai', 'Mirugaseersham', 'Punarpoosam', 'Uthram', 
                                 'Chithirai', 'Anusham', 'Uthradam', 'Sadhayam'])
            }
        }
    
    def _initialize_female_to_male_table(self):
        """Initialize the complete female star to male star matching table"""
        self.female_to_male = {
            'ASWINI': {
                'Rasi': 'Mesha Rasi',
                'Utthamam': (8, ['Bharani', 'Thiruvadhirai', 'Poosam', 'Anusham', 'Pooradam', 
                                'Thiruvonam', 'Sadhayam', 'Utrattadhi']),
                'Madhyamam': (10, ['Poorattathi', 'Avittam', 'Uthradam', 'Visakam', 'Pooram',
                                  'Punarpoosam', 'Mirugaseersham 3&4', 'Chithirai', 'Rohini', 
                                  'Krithigai 1'])
            },
            
            'BHARANI': {
                'Rasi': 'Mesha Rasi',
                'Utthamam': (11, ['Aswini', 'Krithigai 1st', 'Mirugaseersham 3&4', 'Punarpoosam', 
                                 'Ayilyum', 'Chithirai 3&4', 'Visakam', 'Kettai', 'Moolam', 
                                 'Uthradam', 'Revathi']),
                'Madhyamam': (7, ['Sadhayam', 'Thiruvonam', 'Swathi', 'Thiruvadhirai',
                                 'Krithigai 2,3&4', 'Magam', 'Visakam 4th'])
            },
            
            'KRITHIKAI': {
                '1st Padham': {
                    'Rasi': 'Mesha Rasi',
                    'Utthamam': (10, ['Aswini', 'Bharani', 'Thiruvadhirai', 'Poosam', 'Hastham', 
                                     'Swathi', 'Anusham', 'Moolam', 'Sadhayam', 'Uthirattadhi']),
                    'Madhyamam': (6, ['Mirugaseersham 3&4', 'Maham', 'Chithirai', 'Kettai', 
                                     'Avittam', 'Revathy'])
                },
                '2-3-4th Padhas': {
                    'Rasi': 'Rishaba Rasi',
                    'Utthamam': (9, ['Aswini', 'Bharani', 'Poosam', 'Maham', 'Swathi', 'Anusham',
                                    'Moolam', 'Sadhayam', 'Uthirattathi']),
                    'Madhyamam': (7, ['Revathy', 'Avittam', 'Kettai', 'Hastham', 'Pooram', 'Rohini'])
                }
            },
            
            'ROHINI': {
                'Rasi': 'Rishaba Rasi',
                'Utthamam': (13, ['Bharani', 'Krithikai', 'Mirugaseerusham', 'Punarpoosam 4', 
                                 'Ayilyum', 'Utthiram 1', 'Chithirai 3&4', 'Visakam', 'Kettai', 
                                 'Uthradam', 'Avittam', 'Poorattathi', 'Revathi']),
                'Madhyamam': (5, ['Uthirattathi', 'Anusham', 'Poosam', 'Punarpoosam 1-2&3', 'Aswini'])
            },
            
            'MIRUGASEERSHAM': {
                '1&2nd Padham': {
                    'Rasi': 'Rishaba Rasi',
                    'Utthamam': (11, ['Aswini', 'Krithigai', 'Rohini', 'Poosam', 'Uthiram 1st', 
                                     'Anusham', 'Moolam', 'Uthradam 2,3&4', 'Thiruvonam', 
                                     'Sadhayam', 'Uthrattathi']),
                    'Madhyamam': (9, ['Revathi', 'Poorattathi', 'Kettai', 'Visagam', 'Ayilyum', 
                                     'Swathi', 'Punarpoosam 4', 'Bharani', 'Pooradam'])
                },
                '3&4th Padham': {
                    'Rasi': 'Mithuna Rasi',
                    'Utthamam': (12, ['Aswini', 'Krithigai', 'Rohini', 'Thiruvadhirai', 'Uthiram', 
                                     'Hastham', 'Anusham', 'Moolam', 'Uthiradam 1', 'Thiruvonam', 
                                     'Sadhyam', 'Uthirattathi']),
                    'Madhyamam': (9, ['Revathy', 'Poorattathi', 'Kettai', 'Swati', 'Visakam', 
                                     'Poosam', 'Pooradam', 'Punarpoosam 1,2&3', 'Bharani'])
                }
            },
            
            'THIRUVADHIRAI': {
                'Rasi': 'Mithunarasi',
                'Utthamam': (10, ['Bharani', 'Mirugaseersham', 'Punarpoosam 1,2&3', 'Pooram', 
                                 'Chithirai 1&2', 'Pooradam', 'Avittam', 'Visakam 4th', 
                                 'Poorattathi', 'Revathy']),
                'Madhyamam': (8, ['Uthrattathi', 'Uthradam', 'Moolam', 'Uthram', 'Magam', 
                                 'Punarpoosam 4th', 'Krithigai', 'Aswini'])
            },
            
            'PUNARPOOSAM': {
                '1,2,3': {
                    'Rasi': 'Mithuna Rasi',
                    'Utthamam': (10, ['Aswini', 'Mirugaseersham', 'Thiruvadhirai', 'Poosam', 
                                     'Chithirai 1&2', 'Anusham', 'Moolam', 'Avittam', 'Sadhyam', 
                                     'Uthrattathi']),
                    'Madhyamam': (10, ['Revathi', 'Thiruvonam', 'Pooradam', 'Kettai', 'Hastham', 
                                      'Poosam', 'Ayilyum', 'Chithirai 3&4', 'Swathi', 'Rohini'])
                },
                '4th Padham': {
                    'Rasi': 'Kadaka Rasi',
                    'Utthamam': (11, ['Aswini', 'Mirugaseersham', 'Thituvadhirai', 'Poosam', 
                                     'Chithirai', 'Swathi', 'Anusham', 'Moolam', 'Avittam', 
                                     'Uthrattathi', 'Sadhayam']),
                    'Madhyamam': (8, ['Revathy', 'Thiruvonam', 'Kettai', 'Pooradam', 'Hastham', 
                                     'Ayilyum', 'Rohini', 'Bharani'])
                }
            },
            
            'POOSAM': {
                'Rasi': 'Kadaka Rasi',
                'Utthamam': (10, ['Rohini', 'Thiruvadhirai', 'Punarpoosam', 'Ayilyum', 'Hastham', 
                                 'Swathi', 'Visakam', 'Poorattathi', 'Revathi', 'Sadhayam']),
                'Madhyamam': (9, ['Aswini', 'Krithigai', 'Mirugaseersham', 'Uthiram', 'Chithirai', 
                                 'Moolam', 'Uthradam 2,3&4', 'Avittam', 'Magam'])
            },
            
            'AYILYUM': {
                'Rasi': 'Kadaka Rasi',
                'Utthamam': (10, ['Krithigai', 'Mirugaseershm', 'Punarpoosam', 'Poosam', 'Chithirai', 
                                 'Visakam 1,2&3', 'Anusham', 'Avittam', 'Poorattathi', 
                                 'Utthirattathi']),
                'Madhyamam': (8, ['Bharani', 'Rohini', 'Thiruvadhirai', 'Hastham', 
                                 'Uthiram 2,3&4', 'Uthradam', 'Thiruvonam', 'Sadhayam'])
            },
            
            'MAGAM': {
                'Rasi': 'Simma Rasi',
                'Utthamam': (8, ['Bharani', 'Thiruvadhirai', 'Poosam', 'Swathi', 'Anusham', 
                                'Thiruvonam', 'Sadhayam', 'Utthirattathi']),
                'Madhyamam': (6, ['Krithigai', 'Pooram', 'Chithirai 3&4', 'Hastham', 'Avittam', 
                                 'Poorattathi'])
            },
            
            'POORAM': {
                'Rasi': 'Simma Rasi',
                'Utthamam': (12, ['Aswini', 'Krithigai', 'Thiruvadhirai', 'Magam', 'Uthiram1', 
                                 'Chithirai3&4', 'Visakam', 'Kettai', 'Uthradam2.3&4', 'Avittam', 
                                 'Poorattathi', 'Revathi']),
                'Madhyamam': (5, ['Thiruvadhirai', 'Swathi', 'Moolam', 'Thiruvonam', 'Sadhayam'])
            },
            
            'UTHIRAM': {
                '1st Padham': {
                    'Rasi': 'Simma Rasi',
                    'Utthamam': (12, ['Aswini', 'Bharani', 'Rohini', 'Thiruvadhirai', 'Poosam', 
                                     'Magam', 'Pooram', 'Swathi', 'Anusham', 'Thiruvonam', 
                                     'Sadhayam', 'Utthirattathi']),
                    'Madhyamam': (7, ['Revathi', 'Avittam', 'Kettai', 'Ayilyum', 'Mirugaseerusham', 
                                     'Pooradam', 'Moolam'])
                },
                '2-3&4 Padham': {
                    'Rasi': 'Kanni Rasi',
                    'Utthamam': (13, ['Aswini', 'Bharani', 'Rohini', 'Thiruvadhirai', 'Poosam', 
                                     'Magam', 'Pooram', 'Hastham', 'Anusham', 'Moolam', 'Pooradam', 
                                     'Sadhayam', 'Utthirattathi']),
                    'Madhyamam': (6, ['Revathi', 'Avittam 3&4', 'Kettai', 'Swarhi', 'Ayilyum', 
                                     'Mirugaseerusham'])
                }
            },
            
            'HASTHAM': {
                'Rasi': 'Kanni Rasi',
                'Utthamam': (15, ['Bharani', 'Krithigai', 'Mirugaseerusham', 'Punarpoosam', 
                                 'Ayilyum', 'Pooram', 'Uthiram', 'Chithirai 1&2', 'Visakam 4th', 
                                 'Kettai', 'Pooradam', 'Uthradam 1st', 'Avittam 3&4', 
                                 'Poorattathi', 'Revathi']),
                'Madhyamam': (4, ['Poosam', 'Magam', 'Anusham', 'Uthirattadhi'])
            },
            
            'CHITHIRAI': {
                '1&2nd Padham': {
                    'Rasi': 'Kanni Rasi',
                    'Utthamam': (10, ['Aswini', 'Krithigai', 'Rohini', 'Thiruvadhirai', 'Poosam', 
                                     'Magam', 'Hastham', 'Anusham', 'Moolam', 'Sadhayam']),
                    'Madhyamam': (6, ['Revathi', 'Visakam', 'Pooram', 'Ayilyum', 'Punarpoosam', 
                                     'Bharani'])
                },
                '3&4th Padha': {
                    'Rasi': 'Thula Rasi',
                    'Utthamam': (9, ['Aswini', 'Krithigai', 'Rohini', 'Thiruvadhirai', 'Poosam', 
                                    'Hastham', 'Swathi', 'Moolam', 'Thiruvonam']),
                    'Madhyamam': (7, ['Revathi', 'Visakam', 'Pooram', 'Kettai', 'Ayilyum', 
                                     'Punarpoosam', 'Bharani'])
                }
            },
            
            'SWATHI': {
                'Rasi': 'Thula Rasi',
                'Utthamam': (10, ['Bharani', 'Mirugaseerusham 3&4', 'Punarpoosam', 'Ayilyum', 
                                 'Kettai', 'Pooradam', 'Pooram', 'Chithirai', 'Visakam', 'Revathi']),
                'Madhyamam': (9, ['Utthirattathi', 'Uthiram', 'Uthradam', 'Krithigai', 'Poosam', 
                                 'Magam', 'Moolam', 'Poorattadhi', 'Avittam 1&2'])
            },
            
            'VISAKAM': {
                '1,2,3 Padham': {
                    'Rasi': 'Thula Rasi',
                    'Utthamam': (9, ['Aswini', 'Mirugaseerusham', 'Thiruvadhirai', 'Poosam', 
                                    'Magam', 'Chithirai', 'Swathi', 'Moolam', 'Avittam 1&2']),
                    'Madhyamam': (10, ['Revathi', 'Hastham', 'Pooram', 'Ayilyum', 'Rohini', 
                                      'Bharani', 'Anusham', 'Kettai', 'Avittam 3&4', 'Sadhayam'])
                },
                '4th Padham': {
                    'Rasi': 'Vrichika Rasi',
                    'Utthamam': (11, ['Aswini', 'Mirugaseerusham', 'Thiruvadhirai', 'Poosam', 
                                     'Magam', 'Chithirai', 'Swathi', 'Anusham', 'Moolam', 
                                     'Avittam', 'Sadhayam']),
                    'Madhyamam': (7, ['Kettai', 'Hastham', 'Pooram', 'Rohini', 'Bharani', 
                                     'Ayilyum', 'Revathy'])
                }
            },
            
            'ANUSHAM': {
                'Rasi': 'Vrichika Rasi',
                'Utthamam': (9, ['Rohini', 'Punarpoosam', 'Ayilyum', 'Hastham', 'Swathi', 
                                'Visakam', 'Sadhayam', 'Thiruvonam', 'Poorattathi 1,2&3']),
                'Madhyamam': (10, ['Revathy', 'Poorattadhi', 'Kettai', 'Chithirai', 'Uthradam 2,3&4', 
                                  'Uthiram', 'Magam', 'Mirugaseerusham', 'Krithigai', 'Aswini'])
            },
            
            'KETTAI': {
                'Rasi': 'Vrichika Rasi',
                'Utthamam': (10, ['Krithigai', 'Mirugaseerusham', 'Punarpoosam', 'Poosam', 
                                 'Uthiram', 'Chithirai', 'Visakam', 'Anusham', 'Avittam']),
                'Madhyamam': (9, ['Uthirattadhi', 'Poorattadhi', 'Thiruvonam', 'Uthradam', 
                                 'Hastham', 'Swathi', 'Pooram', 'Rohini', 'Bharani'])
            },
            
            'MOOLAM': {
                'Rasi': 'Dhanur Rasi',
                'Utthamam': (6, ['Thiruvadhirai', 'Poosam', 'Pooram', 'Hastham', 'Swathi', 
                                'Sadhayam']),
                'Madhyamam': (9, ['Utthirattathi', 'Visakam', 'Chithirai', 'Uthiram', 
                                 'Punarpoosam', 'Mirugaseerusham 3&4', 'Pooradam', 
                                 'Thiruvonam', 'Avittam'])
            },
            
            'POORADAM': {
                'Rasi': 'Dhanur Rasi',
                'Utthamam': (11, ['Mirugaseersham', 'Punarpoosam 1,2&3', 'Magam', 'Uthiram', 
                                 'Chithirai', 'Visakam', 'Kettai', 'Moolam', 'Uthradam 1st', 
                                 'Poorattathi', 'Revathi']),
                'Madhyamam': (8, ['Thiruvadhirai', 'Ayilyum', 'Punarpoosam 4th', 'Hastham', 
                                 'Swathi', 'Uthradam 2,3&4', 'Thiruvonam', 'Avittam'])
            },
            
            'UTHRADAM': {
                '1st Padham': {
                    'Rasi': 'Dhanur Rasi',
                    'Utthamam': (11, ['Thiruvadhirai', 'Poosam', 'Magam', 'Pooram', 'Hastham', 
                                     'Swathi', 'Anusham', 'Moolam', 'Pooradam', 'Sadhayam', 
                                     'Utthirattathi']),
                    'Madhyamam': (8, ['Aswini', 'Bharani', 'Mirugaseerusham', 'Ayilyum', 'Kettai', 
                                     'Thiruvonam', 'Avittam', 'Revathy'])
                },
                '2,3,4 Padham': {
                    'Rasi': 'Makara Rasi',
                    'Utthamam': (13, ['Aswini', 'Bharani', 'Poosam', 'Magam', 'Pooram', 'Hastham', 
                                     'Swathi', 'Anusham', 'Moolam', 'Pooradam', 'Thiruvonam', 
                                     'Sadhayam', 'Utthirattathi']),
                    'Madhyamam': (5, ['Rohini', 'Ayilyum', 'Kettai', 'Avittam', 'Revathy'])
                }
            },
            
            'THIRUVONAM': {
                'Rasi': 'Makara Rasi',
                'Utthamam': (12, ['Bharani', 'Mirugaseerusham', 'Punarpoosam', 'Ayilyum', 
                                 'Uthiram 2,3&4', 'Chithirai', 'Pooram', 'Visakam', 'Kettai', 
                                 'Pooradam', 'Uthradam', 'Avittam', 'Poorattathi', 'Revathi']),
                'Madhyamam': (6, ['Magam', 'Pooram', 'Uthiram 1', 'Anusham', 'Moolam', 
                                 'Uthirattadhi'])
            },
            
            'AVITTAM': {
                '1&2 Padham': {
                    'Rasi': 'Makara Rasi',
                    'Utthamam': (11, ['Aswini', 'Krithigai', 'Poosam', 'Uthiram 2,3&4', 'Hastham', 
                                     'Swathi', 'Anusham', 'Moolam', 'Uthradam', 'Thiruvonam', 
                                     'Sadhayam']),
                    'Madhyamam': (9, ['Utthirattathi', 'Pooradam', 'Visakam', 'Ayilyum', 
                                     'Punarpoosam', 'Krithigai2,3&4', 'Kettai', 'Uthram', 'Magam'])
                },
                '3&4 Padham': {
                    'Rasi': 'Kumba Rasi',
                    'Utthamam': (11, ['Krithigai', 'Poosam', 'Magam', 'Uthram', 'Hastham', 
                                     'Swathi', 'Anusham', 'Moolam', 'Uthradam', 'Thiruvonam', 
                                     'Sadhayam']),
                    'Madhyamam': (10, ['Pooradam', 'Kettai', 'Visakam', 'Pooram', 'Ayilyum', 
                                      'Punarpoosam 4', 'Thiruvadhirai', 'Rohini', 'Aswini', 
                                      'Uthirattadhi'])
                }
            },
            
            'SADHAYAM': {
                'Rasi': 'Kumba Rasi',
                'Utthamam': (9, ['Mirugaseerusham', 'Punarpoosam', 'Ayilyum', 'Pooram', 'Chithirai', 
                                'Visakam', 'Kettai', 'Pooradam', 'Avittam']),
                'Madhyamam': (9, ['Revathi', 'Poorattathi', 'Uthradam', 'Moolam', 'Anusham', 
                                 'Uthiram', 'Poosam', 'Ponarpoosam', 'Aswini'])
            },
            
            'POORATTATHI': {
                '1,2,3 Padham': {
                    'Rasi': 'Kumba Rasi',
                    'Utthamam': (10, ['Aswini', 'Mirugaseerusham 1&2', 'Poosam', 'Magam', 
                                     'Chithirai', 'Swathi', 'Anusham', 'Moolam', 'Avittam', 
                                     'Sadhayam']),
                    'Madhyamam': (7, ['Utthirattathi', 'Thiruvonam', 'Pooradam', 'Kettai', 
                                     'Anusham', 'Hastham', 'Ayilyum'])
                },
                '4th Padham': {
                    'Rasi': 'Meena Rasi',
                    'Utthamam': (8, ['Mirugaseerusham', 'Thiruvadhirai', 'Chithirai 1&2', 
                                    'Anusham', 'Moolam', 'Avittam', 'Sadhayam', 'Utthirattathi']),
                    'Madhyamam': (6, ['Thiruvonam', 'Pooradam', 'Kettai', 'Hastham', 'Poosam', 
                                     'Swathi'])
                }
            },
            
            'UTTHIRATTATHI': {
                'Rasi': 'Meena Rasi',
                'Utthamam': (9, ['Rohini', 'Thiruvadhirai', 'Punarpoosam 2&3', 'Hastham', 
                                'Kettai', 'Thiruvonam', 'Sadhayam', 'Poorattathi', 'Revathi']),
                'Madhyamam': (8, ['Avittam', 'Uthradam', 'Moolam', 'Swathi', 'Ayilyum', 
                                 'Uthram 3&4', 'Punarpoosam 4th', 'Krithigai 2,3&4'])
            },
            
            'REVATHI': {
                'Rasi': 'Meena rasi',
                'Utthamam': (9, ['Krithigai 2,3&4', 'Mirugaseerusham', 'Punarpoosam 1,2 &3', 
                                'Uthiram 2,3&4', 'Chithirai 1&2', 'Visakam', 'Anusham', 
                                'Uthradam', 'Utthirattathi']),
                'Madhyamam': (9, ['Sadhayam', 'Thiruvonam', 'Visakam', 'Hastham', 'Poosam', 
                                 'Pooradam', 'Punarpoosam 4th', 'Rohini', 'Krithigai 1st'])
            }
        }
    
    def get_male_to_female_matches(self, male_star, padham=None):
        """
        Get matching female stars for a given male star
        Args:
            male_star (str): Name of the male's star
            padham (str, optional): Padham if applicable (e.g., '1st Padham', '2-3-4th Padhas')
        Returns:
            dict: Dictionary with 'Rasi', 'Utthamam', and 'Madhyamam' matches
        """
        star_data = self.male_to_female.get(male_star.upper())
        
        if star_data is None:
            return None
            
        # Handle stars with multiple padhams
        if isinstance(star_data.get('1st Padham'), dict):
            if padham:
                padham_key = f"{padham} Padham" if "Padham" not in padham else padham
                return star_data.get(padham_key)
            return star_data
        return star_data
    
    def get_female_to_male_matches(self, female_star, padham=None):
        """
        Get matching male stars for a given female star
        Args:
            female_star (str): Name of the female's star
            padham (str, optional): Padham if applicable
        Returns:
            dict: Dictionary with 'Rasi', 'Utthamam', and 'Madhyamam' matches
        """
        star_data = self.female_to_male.get(female_star.upper())
        
        if star_data is None:
            return None
            
        # Handle stars with multiple padhams
        if isinstance(star_data.get('1st Padham'), dict):
            if padham:
                padham_key = f"{padham} Padham" if "Padham" not in padham else padham
                return star_data.get(padham_key)
            return star_data
        return star_data
    
    def check_compatibility(self, male_star, female_star, male_padham=None, female_padham=None):
        """
        Check compatibility between a male's star and a female's star
        Args:
            male_star (str): Boy's star name
            female_star (str): Girl's star name
            male_padham (str, optional): Boy's padham if applicable
            female_padham (str, optional): Girl's padham if applicable
        Returns:
            dict: Dictionary with compatibility information including:
                  - male_to_female_match: Match info from male's perspective
                  - female_to_male_match: Match info from female's perspective
                  - is_utthamam: Whether it's an Utthamam match from both perspectives
                  - is_madhyamam: Whether it's at least a Madhyamam match from both perspectives
                  - combined_score: Sum of scores from both perspectives
        """
        male_data = self.get_male_to_female_matches(male_star, male_padham)
        female_data = self.get_female_to_male_matches(female_star, female_padham)
        
        if not male_data or not female_data:
            return None
        
        # Check if female_star is in male's Utthamam list
        male_utthamam = female_star.upper() in [s.upper() for s in male_data['Utthamam'][1]]
        male_madhyamam = female_star.upper() in [s.upper() for s in male_data['Madhyamam'][1]]
        
        # Check if male_star is in female's Utthamam list
        female_utthamam = male_star.upper() in [s.upper() for s in female_data['Utthamam'][1]]
        female_madhyamam = male_star.upper() in [s.upper() for s in female_data['Madhyamam'][1]]
        
        # Calculate scores
        male_score = male_data['Utthamam'][0] if male_utthamam else (
            male_data['Madhyamam'][0] if male_madhyamam else 0)
        female_score = female_data['Utthamam'][0] if female_utthamam else (
            female_data['Madhyamam'][0] if female_madhyamam else 0)
        
        return {
            'male_to_female_match': {
                'is_utthamam': male_utthamam,
                'is_madhyamam': male_madhyamam,
                'score': male_score,
                'matches': male_data['Utthamam'][1] if male_utthamam else (
                    male_data['Madhyamam'][1] if male_madhyamam else [])
            },
            'female_to_male_match': {
                'is_utthamam': female_utthamam,
                'is_madhyamam': female_madhyamam,
                'score': female_score,
                'matches': female_data['Utthamam'][1] if female_utthamam else (
                    female_data['Madhyamam'][1] if female_madhyamam else [])
            },
            'is_utthamam': male_utthamam and female_utthamam,
            'is_madhyamam': (male_utthamam or male_madhyamam) and (female_utthamam or female_madhyamam),
            'combined_score': male_score + female_score,
            'male_rasi': male_data['Rasi'],
            'female_rasi': female_data['Rasi']
        }


# Example usage with a simple command-line interface
if __name__ == "__main__":
    matcher = NakshatraMatcher()
    
    print("Nakshatra Matching System")
    print("------------------------")
    
    while True:
        print("\nOptions:")
        print("1. Check compatibility between male and female stars")
        print("2. Get matches for a male's star")
        print("3. Get matches for a female's star")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == "1":
            male_star = input("Enter male's star: ").strip().upper()
            female_star = input("Enter female's star: ").strip().upper()
            
            # Check if stars have padham variations
            male_padham = None
            female_padham = None
            
            male_data = matcher.male_to_female.get(male_star, {})
            if isinstance(male_data.get('1st Padham'), dict):
                print(f"\n{male_star} has multiple padhams:")
                for key in male_data.keys():
                    if "Padham" in key:
                        print(f"- {key}")
                male_padham = input("Enter male's padham (or leave blank if not applicable): ").strip()
            
            female_data = matcher.female_to_male.get(female_star, {})
            if isinstance(female_data.get('1st Padham'), dict):
                print(f"\n{female_star} has multiple padhams:")
                for key in female_data.keys():
                    if "Padham" in key:
                        print(f"- {key}")
                female_padham = input("Enter female's padham (or leave blank if not applicable): ").strip()
            
            result = matcher.check_compatibility(male_star, female_star, male_padham, female_padham)
            
            if result:
                print("\nCompatibility Results:")
                print(f"Boy's Rasi: {result['male_rasi']}")
                print(f"Girl's Rasi: {result['female_rasi']}")
                print("\nFrom Boy's perspective:")
                print(f"Match type: {'Utthamam' if result['male_to_female_match']['is_utthamam'] else 'Madhyamam' if result['male_to_female_match']['is_madhyamam'] else 'No match'}")
                print(f"Score: {result['male_to_female_match']['score']}")
                
                print("\nFrom Girl's perspective:")
                print(f"Match type: {'Utthamam' if result['female_to_male_match']['is_utthamam'] else 'Madhyamam' if result['female_to_male_match']['is_madhyamam'] else 'No match'}")
                print(f"Score: {result['female_to_male_match']['score']}")
                
                print("\nOverall:")
                print(f"Combined score: {result['combined_score']}")
                print(f"Is mutual Utthamam match: {'Yes' if result['is_utthamam'] else 'No'}")
                print(f"Is at least mutual Madhyamam match: {'Yes' if result['is_madhyamam'] else 'No'}")
            else:
                print("Invalid star names entered. Please try again.")
                
        elif choice == "2":
            star = input("Enter male's star: ").strip().upper()
            padham = None
            
            star_data = matcher.male_to_female.get(star, {})
            if isinstance(star_data.get('1st Padham'), dict):
                print(f"\n{star} has multiple padhams:")
                for key in star_data.keys():
                    if "Padham" in key:
                        print(f"- {key}")
                padham = input("Enter padham (or leave blank if not applicable): ").strip()
            
            matches = matcher.get_male_to_female_matches(star, padham)
            
            if matches:
                print("\nMatching Girl Stars:")
                print(f"Rasi: {matches['Rasi']}")
                print("\nUtthamam Matches:")
                print(f"Score: {matches['Utthamam'][0]}")
                print("Stars:", ", ".join(matches['Utthamam'][1]))
                
                print("\nMadhyamam Matches:")
                print(f"Score: {matches['Madhyamam'][0]}")
                print("Stars:", ", ".join(matches['Madhyamam'][1]))
            else:
                print("Invalid star name entered. Please try again.")
                
        elif choice == "3":
            star = input("Enter female's star: ").strip().upper()
            padham = None
            
            star_data = matcher.female_to_male.get(star, {})
            if isinstance(star_data.get('1st Padham'), dict):
                print(f"\n{star} has multiple padhams:")
                for key in star_data.keys():
                    if "Padham" in key:
                        print(f"- {key}")
                padham = input("Enter padham (or leave blank if not applicable): ").strip()
            
            matches = matcher.get_female_to_male_matches(star, padham)
            
            if matches:
                print("\nMatching Boy Stars:")
                print(f"Rasi: {matches['Rasi']}")
                print("\nUtthamam Matches:")
                print(f"Score: {matches['Utthamam'][0]}")
                print("Stars:", ", ".join(matches['Utthamam'][1]))
                
                print("\nMadhyamam Matches:")
                print(f"Score: {matches['Madhyamam'][0]}")
                print("Stars:", ", ".join(matches['Madhyamam'][1]))
            else:
                print("Invalid star name entered. Please try again.")
                
        elif choice == "4":
            print("Exiting...")
            break
            
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")