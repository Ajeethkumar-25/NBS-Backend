from app import (app, settings, Any, logger, twilio_client, pwd_context,
                 TWILIO_PHONE_NUMBER, RASHI_COMPATIBILITY, NAKSHATRA_COMPATIBILITY, 
                 OTPRequest, OTPVerify, Dict,  datetime, timedelta, HTTPException, re, RefreshTokenRequest,
                 S3Handler, EmailStr, Optional, UploadFile, List, psycopg2, RealDictCursor, TokenResponse, 
                 MatrimonyToken, MatrimonyLoginRequest, traceback, timezone, IncrementMatrimonyIdRequest, 
                 MatrimonyProfileResponse, jwt, DictCursor, ValidationError, time, CompatibilityRequest,
                 generate_otp, get_db_connection, Form, File, generate_matrimony_id, create_access_token, create_refresh_token,
                 Depends, Query, get_current_user_matrimony, send_push_notification)
from astrology_terms import ASTROLOGY_TERMS
# Matrimony Endpoints
@app.post("/matrimony/send-otp", response_model=Dict[str, Any])
async def send_otp(request: OTPRequest):
    logger.info(f"Received OTPRequest: {request}")
    mobile_number = request.mobile_number
    full_name = request.full_name  # This should be available now
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    
    # Save OTP and full_name to PostgreSQL
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Delete any existing OTP for the mobile number
        cur.execute(
            "DELETE FROM otp_storage WHERE mobile_number = %s",
            (mobile_number,)
        )
        
        # Insert new OTP and full_name
        cur.execute(
            """
            INSERT INTO otp_storage (mobile_number, full_name, otp, expires_at)
            VALUES (%s, %s, %s, %s)
            """,
            (mobile_number, full_name, otp, expires_at)
        )
        conn.commit()
        
        # Send OTP via Twilio
        try:
            message = twilio_client.messages.create(
                body=f"Your OTP is {otp}. It will expire in 5 minutes.",
                from_=TWILIO_PHONE_NUMBER,
                to=mobile_number
            )
            logger.info(f"OTP sent to {mobile_number}: {otp}")
            return {"message": "OTP sent successfully", "mobile_number": mobile_number, "full_name": full_name}
        except Exception as e:
            logger.error(f"Failed to send OTP via Twilio: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to send OTP: {str(e)}")
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.post("/matrimony/verify-otp", response_model=Dict[str, Any])
async def verify_otp(request: OTPVerify):
    mobile_number = request.mobile_number
    otp = request.otp
    full_name = request.full_name  # Added full_name
    
    # Fetch OTP and full_name from PostgreSQL
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT otp, full_name, expires_at FROM otp_storage
            WHERE mobile_number = %s AND expires_at > NOW()
            """,
            (mobile_number,)
        )
        db_otp = cur.fetchone()
        
        if not db_otp or db_otp[0] != otp or db_otp[1] != full_name:
            raise HTTPException(status_code=400, detail="Invalid OTP or full name")
        
        # Delete OTP after verification
        cur.execute(
            "DELETE FROM otp_storage WHERE mobile_number = %s",
            (mobile_number,)
        )
        conn.commit()
        
        return {"message": "OTP verified successfully", "mobile_number": mobile_number, "full_name": full_name}
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        cur.close()
        conn.close()
        
        
def convert_empty_to_none(value):
    """ Convert empty strings to None (NULL in PostgreSQL) """
    return None if value == "" else value

@app.post("/matrimony/register")
async def register_matrimony(
    full_name: str = Form(...),
    age: str = Form(...),  # Store as string
    gender: str = Form(...),
    date_of_birth: str = Form(...),  # Store as string
    email: EmailStr = Form(...),
    password: str = Form(...),
    phone_number: str = Form(...),
    height: Optional[str] = Form(None),
    weight: Optional[str] = Form(None),
    occupation: Optional[str] = Form(None),
    annual_income: Optional[str] = Form(None),
    education: Optional[str] = Form(None),
    mother_tongue: Optional[str] = Form(None),
    profile_created_by: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    work_type: Optional[str] = Form(None),
    company: Optional[str] = Form(None),
    work_location: Optional[str] = Form(None),
    work_country: Optional[str] = Form(None),
    mother_name: Optional[str] = Form(None),
    father_name: Optional[str] = Form(None),
    sibling_count: Optional[str] = Form(None),
    elder_brother: Optional[str] = Form(None),
    elder_sister: Optional[str] = Form(None),
    younger_sister: Optional[str] = Form(None),
    younger_brother: Optional[str] = Form(None),
    native: Optional[str] = Form(None),
    mother_occupation: Optional[str] = Form(None),
    father_occupation: Optional[str] = Form(None),
    religion: Optional[str] = Form(None),
    caste: Optional[str] = Form(None),
    sub_caste: Optional[str] = Form(None),
    nakshatra: Optional[str] = Form(None),
    rashi: Optional[str] = Form(None),
    other_dhosham: Optional[str] = Form(None),
    quarter: Optional[str] = Form(None),
    birth_time: Optional[str] = Form(None),
    birth_place: Optional[str] = Form(None),
    ascendent: Optional[str] = Form(None),
    dhosham: Optional[str] = Form(None),
    user_type: Optional[str] = Form(None),
    marital_status:Optional[str]=Form(None),
    preferred_age_min: Optional[str] = Form(None),
    preferred_age_max: Optional[str] = Form(None),
    preferred_height_min: Optional[str] = Form(None),
    preferred_height_max: Optional[str] = Form(None),
    preferred_religion: Optional[str] = Form(None),
    preferred_caste: Optional[str] = Form(None),
    preferred_sub_caste: Optional[str] = Form(None),
    preferred_nakshatra: Optional[str] = Form(None),
    preferred_rashi: Optional[str] = Form(None),
    preferred_location: Optional[str] = Form(None),
    preferred_work_status: Optional[str] = Form(None),
    photo: Optional[UploadFile] = File(None),
    photos: Optional[List[UploadFile]] = File(None),
    horoscope_documents: Optional[List[UploadFile]] = File(None),
    matrimony_id: Optional[str] = Form(None)

):
    try:
        # Initialize S3 Handler
        s3_handler = S3Handler()

        # Hash password
        hashed_password = pwd_context.hash(password)

        # Process profile photo
        photo_url = None
        if photo:
            try:
                photo_url = s3_handler.upload_to_s3(photo, "profile_photos")
                logger.info(f"Profile photo uploaded to: {photo_url}")
            except Exception as e:
                logger.error(f"Profile photo upload failed: {str(e)}")
                raise HTTPException(status_code=400, detail="Profile photo upload failed")

        # Process multiple photos
        photos_urls = []
        if photos:
            for p in photos:
                try:
                    url = s3_handler.upload_to_s3(p, "photos")
                    photos_urls.append(url)
                    logger.info(f"Uploaded photo: {url}")
                except Exception as e:
                    logger.error(f"Photo upload failed: {str(e)}")
                    continue

        # Process horoscope documents
        horoscope_urls = []
        if horoscope_documents:
            for h in horoscope_documents:
                try:
                    url = s3_handler.upload_to_s3(h, "horoscopes")
                    horoscope_urls.append(url)
                    logger.info(f"Uploaded horoscope: {url}")
                except Exception as e:
                    logger.error(f"Horoscope upload failed: {str(e)}")
                    continue

        # Convert to PostgreSQL array format
        def format_array(urls):
            return "{" + ",".join(urls) + "}" if urls else None

        photos_array = format_array(photos_urls)
        horoscope_array = format_array(horoscope_urls)

        # Debug logging
        logger.info(f"Files processed - Profile: {photo_url}, Photos: {photos_array}, Horoscopes: {horoscope_array}")

        # Generate Matrimony ID
        matrimony_id = generate_matrimony_id()

        # # Convert lists to PostgreSQL array format
        # photos_array = '{' + ','.join(photos_urls) + '}' if photos_urls else None
        # horoscope_array = '{' + ','.join(horoscope_urls) + '}' if horoscope_urls else None

        # Convert empty strings to None
        values = tuple(convert_empty_to_none(v) for v in [
            matrimony_id, full_name, age, gender, date_of_birth,
            email, hashed_password, phone_number, height, weight,
            occupation, annual_income, education, mother_tongue,
            profile_created_by, address, work_type, company,
            work_location, work_country, mother_name, father_name,
            sibling_count, elder_brother, elder_sister, younger_sister, younger_brother,
            native, mother_occupation, father_occupation, religion, caste,
            sub_caste, nakshatra, rashi, birth_time, birth_place,
            ascendent, user_type, preferred_age_min, preferred_age_max,
            preferred_height_min, preferred_height_max, preferred_religion,
            preferred_caste, preferred_sub_caste, preferred_nakshatra,
            preferred_rashi, preferred_location, preferred_work_status,
            photo_url, photos_array, horoscope_array, dhosham, other_dhosham, quarter, marital_status
              
        ])

        # Database connection using settings
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Insert into DB
        query = f"""
        INSERT INTO matrimony_profiles (
            matrimony_id, full_name, age, gender, date_of_birth,
            email, password, phone_number, height, weight, occupation,
            annual_income, education, mother_tongue, profile_created_by,
            address, work_type, company, work_location, work_country,
            mother_name, father_name, sibling_count, elder_brother, elder_sister, younger_sister, younger_brother,
            native, mother_occupation, father_occupation,
            religion, caste, sub_caste, nakshatra, rashi, birth_time,
            birth_place, ascendent, user_type, preferred_age_min,
            preferred_age_max, preferred_height_min, preferred_height_max,
            preferred_religion, preferred_caste, preferred_sub_caste,
            preferred_nakshatra, preferred_rashi, preferred_location,
            preferred_work_status, photo_path, photos, 
            horoscope_documents, dhosham, other_dhosham, quarter, marital_status
        ) VALUES (
                {','.join(['%s'] * len(values))}
            ) ON CONFLICT (email) DO NOTHING
            RETURNING matrimony_id
        """

        cur.execute(query, values)
        result = cur.fetchone()
        conn.commit()

        return {
            "status": "success",
            "message": "Profile registered successfully",
            "matrimony_id": result["matrimony_id"] if result else matrimony_id,
            "email": email,
            "password": password
        }

    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        cur.close()
        conn.close()
        
@app.post("/matrimony/login", response_model=MatrimonyToken)
async def login_matrimony(request: MatrimonyLoginRequest):
    try:
        print("Login request received:", request.dict())

        if not request.password and not request.phone_number:
            raise HTTPException(
                status_code=400,
                detail="Either password or phone_number must be provided",
            )

        # Connect to DB
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch user by matrimony_id
        cur.execute(
            "SELECT * FROM matrimony_profiles WHERE matrimony_id = %s",
            (request.matrimony_id,)
        )
        user = cur.fetchone()
        print("Fetched user:", user)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        stored_password = user.get("password")
        stored_phone = user.get("phone_number")

        # Authentication logic
        if request.via_link:
            if not request.password:
                raise HTTPException(status_code=400, detail="Password is required for link login")
            if not stored_password or not pwd_context.verify(request.password, stored_password):
                raise HTTPException(status_code=401, detail="Invalid password for link login")
        else:
            if request.password:
                if not stored_password or not pwd_context.verify(request.password, stored_password):
                    raise HTTPException(status_code=401, detail="Invalid password")
            elif request.phone_number:
                if request.phone_number != stored_phone:
                    raise HTTPException(status_code=401, detail="Invalid phone number")
            else:
                raise HTTPException(status_code=400, detail="Password or phone number is required")

        # Token creation
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["matrimony_id"], "user_type": "user"},
            expires_delta=access_token_expires
        )

        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            data={"sub": user["matrimony_id"], "user_type": "user"},
            expires_delta=refresh_token_expires
        )

        # Save refresh token
        expires_at = datetime.now(timezone.utc) + refresh_token_expires
        cur.execute("""
            INSERT INTO matrimony_refresh_tokens (matrimony_id, token, expires_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (matrimony_id) DO UPDATE
            SET token = EXCLUDED.token,
                expires_at = EXCLUDED.expires_at
        """, (user["matrimony_id"], refresh_token, expires_at))
        conn.commit()

        print("Login successful. Returning tokens.")
        return MatrimonyToken(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error: {type(e).__name__}: {str(e)}")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.get("/matrimony/lastMatrimonyId")
def get_last_matrimony_id():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT matrimony_id FROM matrimony_profiles ORDER BY matrimony_id DESC LIMIT 1;")
        result = cur.fetchone()
        
        cur.close()
        conn.close()

        if result:
            return {"last_matrimony_id": result[0]}
        else:
            return {"last_matrimony_id": 11111}  # Default if no entry exists

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# Endpoint to update the last matrimony ID in the database
@app.put("/matrimony/incrementMatrimonyId")
def increment_matrimony_id(request: IncrementMatrimonyIdRequest):
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get the numeric part from the provided last_matrimony_id
        numeric_part = int(re.search(r'\d+', request.last_matrimony_id).group())

        # Increment and generate new matrimony_id
        new_numeric_part = numeric_part + 1
        new_matrimony_id = f"NBS{new_numeric_part:05d}"

        # Insert new ID into tracker table
        insert_query = """
        INSERT INTO matrimony_id_tracker (last_matrimony_id, updated_at)
        VALUES (%s, CURRENT_TIMESTAMP)
        """
        cur.execute(insert_query, (new_matrimony_id,))
        conn.commit()

        return {
            "success": True,
            "last_matrimony_id": new_matrimony_id
        }

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
            
@app.post("/matrimony/refresh-token", response_model=TokenResponse)
async def matrimony_refresh_token(token: RefreshTokenRequest):
    logger.debug(f"Received refresh token: {token.refresh_token}")
    conn = None
    cur = None

    try:
        # Decode JWT token
        payload = jwt.decode(token.refresh_token, settings.REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        logger.debug(f"Decoded refresh token payload: {payload}")

        matrimony_id = payload.get("sub")
        if not matrimony_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token: missing user ID")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        logger.error("JWT decode error:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail="Invalid token format")

    try:
        # DB operations (separate try block)
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT is_valid FROM matrimony_refresh_tokens WHERE token = %s", (token.refresh_token,))
        db_token = cur.fetchone()

        if not db_token or not db_token[0]:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        # Generate and store new tokens
        access_token = create_access_token({"sub": matrimony_id, "user_type": "user"})
        new_refresh_token = create_refresh_token({"sub": matrimony_id, "user_type": "user"})

        cur.execute("UPDATE matrimony_refresh_tokens SET is_valid = false WHERE token = %s", (token.refresh_token,))
        cur.execute("""
            INSERT INTO matrimony_refresh_tokens (matrimony_id, token, expires_at, is_valid)
            VALUES (%s, %s, %s, true)
            ON CONFLICT (matrimony_id) DO UPDATE SET
                token = EXCLUDED.token,
                expires_at = EXCLUDED.expires_at,
                is_valid = true
        """, (matrimony_id, new_refresh_token, datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)))
        conn.commit()

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }

    except HTTPException:
        raise  # Re-raise exact HTTP errors
    except Exception as e:
        logger.error("Unexpected error in /matrimony/refresh-token:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail="Unexpected server error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.get("/matrimony/profiles", response_model=List[MatrimonyProfileResponse])
async def get_matrimony_profiles(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    language: Optional[str] = Query("en", description="Language for response (e.g., 'en', 'ta')")
):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        logger.info(f"Current user: {current_user}")
        logger.info(f"Requested language: {language}")

        query = "SELECT * FROM matrimony_profiles WHERE 1=1"
        params = []

        if current_user["user_type"] != "admin":
            user_gender = current_user.get("gender")
            if not user_gender:
                raise HTTPException(status_code=400, detail="User gender not found")
            opposite_gender = "Female" if user_gender.lower() == "male" else "Male"
            query += " AND gender ILIKE %s"
            params.append(opposite_gender)
            logger.info(f"Filtering opposite gender: {opposite_gender}")

        cur.execute(query, params)
        profiles = cur.fetchall()
        logger.info(f"Fetched profiles count: {len(profiles)}")

        if not profiles:
            return []

        translator = None
        if language and language.lower() != "en":
            try:
                from googletrans import Translator
                translator = Translator()
                translator.translate("test", src="en", dest=language)
                logger.info(f"Translator initialized for language: {language}")
            except Exception as e:
                logger.error(f"Translator failed to initialize: {e}")
                translator = None

        def process_s3_urls(value, folder_name):
            if value and isinstance(value, str):
                items = [item.strip() for item in value.replace("{", "").replace("}", "").split(',') if item.strip()]
                return [
                    item if item.startswith("http") else
                    f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
                    for item in items
                ] if items else None
            return None

        def translate_static_term(term: str, lang: str) -> str:
            key = term.strip().lower().replace(" ", "_")
            return ASTROLOGY_TERMS.get(key, {}).get(lang, term)

        result_profiles = []

        for profile in profiles:
            profile_dict = dict(profile)

            for key, value in profile_dict.items():
                if isinstance(value, str) and not value.strip():
                    profile_dict[key] = None

            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

            if isinstance(profile_dict.get("date_of_birth"), datetime):
                profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')

            if profile_dict.get("date_of_birth"):
                dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                today = datetime.today()
                profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

            profile_dict["is_translated"] = False
            if translator and language.lower() != "en":
                translatable_fields = [
                    "full_name", "occupation", "gender", "education", "mother_tongue", "dhosham", 
                    "work_type", "company", "work_location", "religion", "caste", "sub_caste"
                ]
                for field in translatable_fields:
                    if field in profile_dict and isinstance(profile_dict[field], str):
                        try:
                            translated = translator.translate(profile_dict[field], src="en", dest=language)
                            profile_dict[field] = translated.text
                            profile_dict["is_translated"] = True
                        except Exception as e:
                            logger.warning(f"Translation failed for {field}: {e}")

                for astro_field in ["nakshatra", "rashi", "dhosham"]:
                    if profile_dict.get(astro_field):
                        profile_dict[astro_field] = translate_static_term(profile_dict[astro_field], language)
                        profile_dict["is_translated"] = True

            try:
                result_profiles.append(MatrimonyProfileResponse(**profile_dict))
            except ValidationError as e:
                logger.error(f"Validation error for {profile_dict.get('matrimony_id')}: {e}")
                continue

        logger.info(f"Returning {len(result_profiles)} profiles")
        return result_profiles

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Server error while fetching profiles.")
    finally:
        cur.close()
        conn.close()
  
@app.get("/matrimony/preference", response_model=List[MatrimonyProfileResponse])
async def get_matrimony_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        # Get complete profile of current user
        cur.execute(
            """
            SELECT matrimony_id, gender, preferred_rashi, preferred_nakshatra, 
                   preferred_religion, rashi, nakshatra, religion
            FROM matrimony_profiles 
            WHERE matrimony_id = %s
            """, 
            [current_user.get("matrimony_id")]
        )
        user_profile = cur.fetchone()
        
        if not user_profile:
            logger.error(f"Profile not found for user: {current_user.get('matrimony_id')}")
            raise HTTPException(status_code=404, detail="User profile not found")

        logger.info(f"Current user exact values - ID: {user_profile['matrimony_id']}, "
                   f"Gender: '{user_profile['gender']}', "
                   f"Preferred Rashi: '{user_profile['preferred_rashi']}', "
                   f"Preferred Nakshatra: '{user_profile['preferred_nakshatra']}', "
                   f"Preferred Religion: '{user_profile['preferred_religion']}'")

        user_gender = user_profile['gender'].strip()
        opposite_gender = "Male" if user_gender.lower() == "female" else "Female"

        # Build query parts based on preferences
        query = """
            SELECT * FROM matrimony_profiles
            WHERE gender ILIKE %s
            AND matrimony_id != %s
        """
        params = [opposite_gender, user_profile['matrimony_id']]

        # Add rashi filter
        if user_profile['preferred_rashi']:
            preferred_rashi_list = [r.strip() for r in user_profile['preferred_rashi'].split(",") if r.strip()]
            if preferred_rashi_list:
                query += """
                    AND rashi IS NOT NULL
                    AND LOWER(rashi) = ANY(SELECT LOWER(UNNEST(%s)))
                """
                params.append(preferred_rashi_list)
                logger.info(f"Filtering by preferred rashi: {preferred_rashi_list}")

        # Add nakshatra filter
        if user_profile['preferred_nakshatra']:
            preferred_nakshatra_list = [n.strip() for n in user_profile['preferred_nakshatra'].split(",") if n.strip()]
            if preferred_nakshatra_list:
                query += """
                    AND nakshatra IS NOT NULL
                    AND LOWER(nakshatra) = ANY(SELECT LOWER(UNNEST(%s)))
                """
                params.append(preferred_nakshatra_list)
                logger.info(f"Filtering by preferred nakshatra: {preferred_nakshatra_list}")

        # Add religion filter
        if user_profile['preferred_religion']:
            preferred_religion_list = [r.strip() for r in user_profile['preferred_religion'].split(",") if r.strip()]
            if preferred_religion_list:
                query += """
                    AND religion IS NOT NULL
                    AND LOWER(religion) = ANY(SELECT LOWER(UNNEST(%s)))
                """
                params.append(preferred_religion_list)
                logger.info(f"Filtering by preferred religion: {preferred_religion_list}")

        logger.info(f"Executing query: {query}")
        logger.info(f"Query params: {params}")
        
        cur.execute(query, params)
        profiles = cur.fetchall()

        if not profiles:
            logger.info("No matching profiles found")
            return []

        compatible_profiles = []
        for profile in profiles:
            profile_dict = dict(zip([desc[0] for desc in cur.description], profile))
            
            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime("%H:%M:%S")
            
            logger.info(f"Found matching profile - ID: {profile_dict['matrimony_id']}, "
                       f"Gender: '{profile_dict['gender']}', "
                       f"Rashi: '{profile_dict.get('rashi')}', "
                       f"Nakshatra: '{profile_dict.get('nakshatra')}', "
                       f"Religion: '{profile_dict.get('religion')}'")
            
            compatible_profiles.append(MatrimonyProfileResponse(**profile_dict))

        return compatible_profiles

    except Exception as e:
        logger.error(f"Error in get_matrimony_preferences: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error retrieving profiles")

    finally:
        cur.close()
        conn.close()

@app.get("/rashi_compatibility/{rashi1}/{rashi2}")
def get_rashi_compatibility(rashi1: str, rashi2: str):
    rashi1, rashi2 = rashi1.lower(), rashi2.lower()
    compatibility = RASHI_COMPATIBILITY.get((rashi1, rashi2)) or RASHI_COMPATIBILITY.get((rashi2, rashi1))
    return {"rashi1": rashi1, "rashi2": rashi2, "compatibility": compatibility or "Unknown"}

@app.get("/nakshatra_compatibility/{nakshatra1}/{nakshatra2}")
def get_nakshatra_compatibility(nakshatra1: str, nakshatra2: str):
    nakshatra1, nakshatra2 = nakshatra1.lower(), nakshatra2.lower()
    compatibility = NAKSHATRA_COMPATIBILITY.get((nakshatra1, nakshatra2)) or NAKSHATRA_COMPATIBILITY.get((nakshatra2, nakshatra1))
    return {"nakshatra1": nakshatra1, "nakshatra2": nakshatra2, "compatibility": compatibility or "Unknown"}

@app.post("/check_compatibility/")
def check_full_compatibility(request: CompatibilityRequest):
    rashi_match = RASHI_COMPATIBILITY.get((request.groom_rashi.lower(), request.bride_rashi.lower()))
    nakshatra_match = NAKSHATRA_COMPATIBILITY.get((request.groom_nakshatra.lower(), request.bride_nakshatra.lower()))
    
    return {
        "groom_rashi": request.groom_rashi,
        "bride_rashi": request.bride_rashi,
        "rashi_compatibility": rashi_match or "Unknown",
        "groom_nakshatra": request.groom_nakshatra,
        "bride_nakshatra": request.bride_nakshatra,
        "nakshatra_compatibility": nakshatra_match or "Unknown"
    }


@app.post("/send-notification", response_model=Dict[str, Any])
async def send_notification(
    token: str = Query(..., description="Device token to send the notification to"),
    title: str = Query(..., description="Title of the notification"),
    body: str = Query(..., description="Body of the notification"),
):
    """
    Send a push notification to a specific device token.
    """
    return send_push_notification(token, title, body)