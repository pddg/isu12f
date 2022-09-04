package main

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// //////////////////////////////////////
// admin

// adminSessionCheckMiddleware
func (h *Handler) adminSessionCheckMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sessID := c.Request().Header.Get("x-session")

		adminSession := new(Session)
		query := "SELECT * FROM admin_sessions WHERE session_id=? AND deleted_at IS NULL"
		if err := h.getAdminDB().Get(adminSession, query, sessID); err != nil {
			if err == sql.ErrNoRows {
				return errorResponse(c, http.StatusUnauthorized, ErrUnauthorized)
			}
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		requestAt, err := getRequestTime(c)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
		}

		if adminSession.ExpiredAt < requestAt {
			query = "UPDATE admin_sessions SET deleted_at=? WHERE session_id=?"
			if _, err = h.getAdminDB().Exec(query, requestAt, sessID); err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			return errorResponse(c, http.StatusUnauthorized, ErrExpiredSession)
		}

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// adminLogin 管理者権限ログイン
// POST /admin/login
func (h *Handler) adminLogin(c echo.Context) error {
	// read body
	defer c.Request().Body.Close()
	req := new(AdminLoginRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	tx, err := h.getAdminDB().Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// userの存在確認
	query := "SELECT * FROM admin_users WHERE id=?"
	user := new(AdminUser)
	if err = tx.Get(user, query, req.UserID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// verify password
	if err = verifyPassword(user.Password, req.Password); err != nil {
		return errorResponse(c, http.StatusUnauthorized, err)
	}

	query = "UPDATE admin_users SET last_activated_at=?, updated_at=? WHERE id=?"
	if _, err = tx.Exec(query, requestAt, requestAt, req.UserID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// すでにあるsessionをdeleteにする
	query = "UPDATE admin_sessions SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = tx.Exec(query, requestAt, req.UserID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// create session
	sID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sessID, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sess := &Session{
		ID:        sID,
		UserID:    req.UserID,
		SessionID: sessID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 86400,
	}

	query = "INSERT INTO admin_sessions(id, user_id, session_id, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?)"
	if _, err = tx.Exec(query, sess.ID, sess.UserID, sess.SessionID, sess.CreatedAt, sess.UpdatedAt, sess.ExpiredAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &AdminLoginResponse{
		AdminSession: sess,
	})
}

type AdminLoginRequest struct {
	UserID   int64  `json:"userId"`
	Password string `json:"password"`
}

type AdminLoginResponse struct {
	AdminSession *Session `json:"session"`
}

// adminLogout 管理者権限ログアウト
// DELETE /admin/logout
func (h *Handler) adminLogout(c echo.Context) error {
	sessID := c.Request().Header.Get("x-session")

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}
	// すでにあるsessionをdeleteにする
	query := "UPDATE admin_sessions SET deleted_at=? WHERE session_id=? AND deleted_at IS NULL"
	if _, err = h.getAdminDB().Exec(query, requestAt, sessID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return noContentResponse(c, http.StatusNoContent)
}

// adminListMaster マスタデータ閲覧
// GET /admin/master
func (h *Handler) adminListMaster(c echo.Context) error {
	masterVersions := getMasterVersions()

	items := getItemMasters()

	gachas := getGachaMasters()

	gachaItems := getGachaItemMasters()

	presentAlls := getPresentAllMasters()

	loginBonuses := getLoginBonusMasters()

	loginBonusRewards := getLoginBonusRewardMasters()

	return successResponse(c, &AdminListMasterResponse{
		VersionMaster:     masterVersions,
		Items:             items,
		Gachas:            gachas,
		GachaItems:        gachaItems,
		PresentAlls:       presentAlls,
		LoginBonuses:      loginBonuses,
		LoginBonusRewards: loginBonusRewards,
	})
}

type AdminListMasterResponse struct {
	VersionMaster     []*VersionMaster          `json:"versionMaster"`
	Items             []*ItemMaster             `json:"items"`
	Gachas            []*GachaMaster            `json:"gachas"`
	GachaItems        []*GachaItemMaster        `json:"gachaItems"`
	PresentAlls       []*PresentAllMaster       `json:"presentAlls"`
	LoginBonusRewards []*LoginBonusRewardMaster `json:"loginBonusRewards"`
	LoginBonuses      []*LoginBonusMaster       `json:"loginBonuses"`
}

// adminUpdateMaster マスタデータ更新
// PUT /admin/master
func (h *Handler) adminUpdateMaster(c echo.Context) error {
	// version master
	versionMasterRecs, err := readFormFileToCSV(c, "versionMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if versionMasterRecs != nil {
		masterVersions := make([]*VersionMaster, 0, len(versionMasterRecs))
		for i, v := range versionMasterRecs {
			if i == 0 {
				continue
			}
			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			status, err := strconv.ParseInt(v[1], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			masterVersions = append(masterVersions, &VersionMaster{
				ID:            id,
				Status:        int(status),
				MasterVersion: v[2],
			})
		}

		cacheMasterVersions(masterVersions)
	} else {
		c.Logger().Debug("Skip Update Master: versionMaster")
	}

	// item
	itemMasterRecs, err := readFormFileToCSV(c, "itemMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if itemMasterRecs != nil {
		itemMasters := make([]*ItemMaster, 0, len(itemMasterRecs))
		for i, v := range itemMasterRecs {
			if i == 0 {
				continue
			}

			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemType, err := strconv.ParseInt(v[1], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			newItemMaster := &ItemMaster{
				ID:          id,
				ItemType:    int(itemType),
				Name:        v[2],
				Description: v[3],
			}
			if v[4] != "" {
				amountPerSec, err := strconv.Atoi(v[4])
				if err != nil {
					c.Logger().Printf("csv data: %v", v)
					return errorResponse(c, http.StatusInternalServerError, err)
				}
				newItemMaster.AmountPerSec = &amountPerSec
			}
			if v[5] != "" {
				maxLevel, err := strconv.Atoi(v[5])
				if err != nil {
					c.Logger().Printf("csv data: %v", v)
					return errorResponse(c, http.StatusInternalServerError, err)
				}
				newItemMaster.MaxLevel = &maxLevel
			}
			if v[6] != "" {
				maxAmountPerSec, err := strconv.Atoi(v[6])
				if err != nil {
					c.Logger().Printf("csv data: %v", v)
					return errorResponse(c, http.StatusInternalServerError, err)
				}
				newItemMaster.MaxAmountPerSec = &maxAmountPerSec
			}
			if v[7] != "" {
				baseExpPerLevel, err := strconv.Atoi(v[7])
				if err != nil {
					c.Logger().Printf("csv data: %v", v)
					return errorResponse(c, http.StatusInternalServerError, err)
				}
				newItemMaster.BaseExpPerLevel = &baseExpPerLevel
			}
			if v[8] != "" {
				gainedExp, err := strconv.Atoi(v[8])
				if err != nil {
					c.Logger().Printf("csv data: %v", v)
					return errorResponse(c, http.StatusInternalServerError, err)
				}
				newItemMaster.GainedExp = &gainedExp
			}
			if v[9] != "" {
				shorteningMin, err := strconv.ParseInt(v[9], 10, 64)
				if err != nil {
					c.Logger().Printf("csv data: %v", v)
					return errorResponse(c, http.StatusInternalServerError, err)
				}
				newItemMaster.ShorteningMin = &shorteningMin
			}

			itemMasters = append(itemMasters, newItemMaster)
		}

		cacheItemMasters(itemMasters)
	} else {
		c.Logger().Debug("Skip Update Master: itemMaster")
	}

	// gacha
	gachaRecs, err := readFormFileToCSV(c, "gachaMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if gachaRecs != nil {
		gachaMasters := make([]*GachaMaster, 0, len(gachaRecs))
		for i, v := range gachaRecs {
			if i == 0 {
				continue
			}

			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			startAt, err := strconv.ParseInt(v[2], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			endAt, err := strconv.ParseInt(v[3], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			displayOrder, err := strconv.ParseInt(v[4], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			createdAt, err := strconv.ParseInt(v[5], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			gachaMasters = append(gachaMasters, &GachaMaster{
				ID:           id,
				Name:         v[1],
				StartAt:      startAt,
				EndAt:        endAt,
				DisplayOrder: int(displayOrder),
				CreatedAt:    createdAt,
			})
		}

		cacheGachaMasters(gachaMasters)

	} else {
		c.Logger().Debug("Skip Update Master: gachaMaster")
	}

	// gacha item
	gachaItemRecs, err := readFormFileToCSV(c, "gachaItemMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if gachaItemRecs != nil {
		gachaItemMasters := make([]*GachaItemMaster, 0, len(gachaItemRecs))
		for i, v := range gachaItemRecs {
			if i == 0 {
				continue
			}

			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			gachaID, err := strconv.ParseInt(v[1], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemType, err := strconv.ParseInt(v[2], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemID, err := strconv.ParseInt(v[3], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			amount, err := strconv.ParseInt(v[4], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			weight, err := strconv.ParseInt(v[5], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			createdAt, err := strconv.ParseInt(v[6], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			gachaItemMasters = append(gachaItemMasters, &GachaItemMaster{
				ID:        id,
				GachaID:   gachaID,
				ItemType:  int(itemType),
				ItemID:    itemID,
				Amount:    int(amount),
				Weight:    int(weight),
				CreatedAt: createdAt,
			})
		}

		cacheGachaItemMasters(gachaItemMasters)
	} else {
		c.Logger().Debug("Skip Update Master: gachaItemMaster")
	}

	// present all
	presentAllRecs, err := readFormFileToCSV(c, "presentAllMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if presentAllRecs != nil {
		presentAllMasters := make([]*PresentAllMaster, 0, len(presentAllRecs))
		for i, v := range presentAllRecs {
			if i == 0 {
				continue
			}

			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			registeredStartAt, err := strconv.ParseInt(v[1], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			registeredEndAt, err := strconv.ParseInt(v[2], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemType, err := strconv.ParseInt(v[3], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemID, err := strconv.ParseInt(v[4], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			amount, err := strconv.ParseInt(v[5], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			createdAt, err := strconv.ParseInt(v[7], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			presentAllMasters = append(presentAllMasters, &PresentAllMaster{
				ID:                id,
				RegisteredStartAt: registeredStartAt,
				RegisteredEndAt:   registeredEndAt,
				ItemType:          int(itemType),
				ItemID:            itemID,
				Amount:            amount,
				PresentMessage:    v[6],
				CreatedAt:         createdAt,
			})
		}

		cachePresentAllMasters(presentAllMasters)
	} else {
		c.Logger().Debug("Skip Update Master: presentAllMaster")
	}

	// login bonuses
	loginBonusRecs, err := readFormFileToCSV(c, "loginBonusMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if loginBonusRecs != nil {
		loginBonusMasters := make([]*LoginBonusMaster, 0, len(loginBonusRecs))
		for i, v := range loginBonusRecs {
			if i == 0 {
				continue
			}
			looped := false
			if v[4] == "TRUE" {
				looped = true
			}
			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			startAt, err := strconv.ParseInt(v[1], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			endAt, err := strconv.ParseInt(v[2], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			columnCount, err := strconv.Atoi(v[3])
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			createdAt, err := strconv.ParseInt(v[5], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			loginBonusMasters = append(loginBonusMasters, &LoginBonusMaster{
				ID:          id,
				StartAt:     startAt,
				EndAt:       endAt,
				ColumnCount: columnCount,
				Looped:      looped,
				CreatedAt:   createdAt,
			})
		}

		cacheLoginBonusMasters(loginBonusMasters)
	} else {
		c.Logger().Debug("Skip Update Master: loginBonusMaster")
	}

	// login bonus rewards
	loginBonusRewardRecs, err := readFormFileToCSV(c, "loginBonusRewardMaster")
	if err != nil {
		if err != ErrNoFormFile {
			return errorResponse(c, http.StatusBadRequest, err)
		}
	}
	if loginBonusRewardRecs != nil {
		loginBonusRewardMasters := make([]*LoginBonusRewardMaster, 0, len(loginBonusRewardRecs))
		for i, v := range loginBonusRewardRecs {
			if i == 0 {
				continue
			}
			id, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			loginBonusID, err := strconv.ParseInt(v[1], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			rewardSequence, err := strconv.ParseInt(v[2], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemType, err := strconv.ParseInt(v[3], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			itemID, err := strconv.ParseInt(v[4], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			amount, err := strconv.ParseInt(v[5], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			createdAt, err := strconv.ParseInt(v[6], 10, 64)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}

			loginBonusRewardMasters = append(loginBonusRewardMasters, &LoginBonusRewardMaster{
				ID:             id,
				LoginBonusID:   loginBonusID,
				RewardSequence: int(rewardSequence),
				ItemType:       int(itemType),
				ItemID:         itemID,
				Amount:         amount,
				CreatedAt:      createdAt,
			})
		}

		cacheLoginBonusRewardMasters(loginBonusRewardMasters)

	} else {
		c.Logger().Debug("Skip Update Master: loginBonusRewardMaster")
	}

	activeMaster := new(VersionMaster)
	for _, mv := range getMasterVersions() {
		if mv.Status == 1 {
			activeMaster = mv
			break
		}
	}
	if activeMaster == nil {
		return errorResponse(c, http.StatusInternalServerError, errors.New("active master version not found"))
	}

	return successResponse(c, &AdminUpdateMasterResponse{
		VersionMaster: activeMaster,
	})
}

type AdminUpdateMasterResponse struct {
	VersionMaster *VersionMaster `json:"versionMaster"`
}

// readFromFileToCSV ファイルからcsvレコードを取得する
func readFormFileToCSV(c echo.Context, name string) ([][]string, error) {
	file, err := c.FormFile(name)
	if err != nil {
		return nil, ErrNoFormFile
	}

	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, src); err != nil {
		return nil, err
	}

	csvReader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	return records, nil
}

// adminUser ユーザの詳細画面
// GET /admin/user/{userID}
func (h *Handler) adminUser(c echo.Context) error {
	var query string

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
	}

	devices := getAllUserDeviceByUser(userID)

	cards := getAllUserCardsByUser(userID)

	decks := getAllUserDeckByUser(userID)

	items := getAllUserItemsByUser(userID)

	loginBonuses := getAllUserLoginBonusByUser(userID)

	query = "SELECT * FROM user_presents WHERE user_id=?"
	presents := make([]*UserPresent, 0)
	if err = h.getUserDB(userID).Select(&presents, query, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	presentHistory := getAllUserPresentReceivedHistoriesByUser(userID)

	return successResponse(c, &AdminUserResponse{
		User:                          user,
		UserDevices:                   devices,
		UserCards:                     cards,
		UserDecks:                     decks,
		UserItems:                     items,
		UserLoginBonuses:              loginBonuses,
		UserPresents:                  presents,
		UserPresentAllReceivedHistory: presentHistory,
	})
}

type AdminUserResponse struct {
	User *User `json:"user"`

	UserDevices                   []*UserDevice                    `json:"userDevices"`
	UserCards                     []*UserCard                      `json:"userCards"`
	UserDecks                     []*UserDeck                      `json:"userDecks"`
	UserItems                     []*UserItem                      `json:"userItems"`
	UserLoginBonuses              []*UserLoginBonus                `json:"userLoginBonuses"`
	UserPresents                  []*UserPresent                   `json:"userPresents"`
	UserPresentAllReceivedHistory []*UserPresentAllReceivedHistory `json:"userPresentAllReceivedHistory"`
}

// adminBanUser ユーザBAN処理
// POST /admin/user/{userId}/ban
func (h *Handler) adminBanUser(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusBadRequest, ErrUserNotFound)
	}

	cacheUserBan(user.ID)

	return successResponse(c, &AdminBanUserResponse{
		User: user,
	})
}

type AdminBanUserResponse struct {
	User *User `json:"user"`
}

//nolint:deadcode,unused
func hashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", ErrGeneratePassword
	}
	return string(hash), nil
}

func verifyPassword(hash, pw string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)); err != nil {
		return ErrUnauthorized
	}
	return nil
}

type AdminUser struct {
	ID              int64  `db:"id"`
	Password        string `db:"password"`
	LastActivatedAt int64  `db:"last_activated_at"`
	CreatedAt       int64  `db:"created_at"`
	UpdatedAt       int64  `db:"updated_at"`
	DeletedAt       *int64 `db:"deleted_at"`
}
