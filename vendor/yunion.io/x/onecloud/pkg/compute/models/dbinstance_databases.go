// Copyright 2019 Yunion
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"context"
	"database/sql"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/util/compare"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/cloudcommon/db/lockman"
	"yunion.io/x/onecloud/pkg/cloudcommon/db/taskman"
	"yunion.io/x/onecloud/pkg/cloudprovider"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/util/rbacutils"
	"yunion.io/x/onecloud/pkg/util/stringutils2"
)

type SDBInstanceDatabaseManager struct {
	db.SStatusStandaloneResourceBaseManager
	db.SExternalizedResourceBaseManager
	SDBInstanceResourceBaseManager
}

var DBInstanceDatabaseManager *SDBInstanceDatabaseManager

func init() {
	DBInstanceDatabaseManager = &SDBInstanceDatabaseManager{
		SStatusStandaloneResourceBaseManager: db.NewStatusStandaloneResourceBaseManager(
			SDBInstanceDatabase{},
			"dbinstancedatabases_tbl",
			"dbinstancedatabase",
			"dbinstancedatabases",
		),
	}
	DBInstanceDatabaseManager.SetVirtualObject(DBInstanceDatabaseManager)
}

type SDBInstanceDatabase struct {
	db.SStatusStandaloneResourceBase
	db.SExternalizedResourceBase

	SDBInstanceResourceBase `width:"36" charset:"ascii" name:"dbinstance_id" nullable:"false" list:"user" create:"required" index:"true"`

	// 字符集
	// example: utf-8
	CharacterSet string `width:"32" charset:"ascii" nullable:"true" list:"user" create:"optional" json:"character_set"`

	// RDS实例Id
	// example: 7d07e867-37d1-4754-865d-80f88ad0f982
	// DBInstanceId string `width:"36" charset:"ascii" name:"dbinstance_id" nullable:"false" list:"user" create:"required" index:"true"`
}

func (manager *SDBInstanceDatabaseManager) GetContextManagers() [][]db.IModelManager {
	return [][]db.IModelManager{
		{DBInstanceManager},
	}
}

func (manager *SDBInstanceDatabaseManager) ResourceScope() rbacutils.TRbacScope {
	return rbacutils.ScopeProject
}

func (self *SDBInstanceDatabase) GetOwnerId() mcclient.IIdentityProvider {
	instance, err := self.GetDBInstance()
	if err != nil {
		log.Errorf("failed to get instance for database %s(%s)", self.Name, self.Id)
		return nil
	}
	return instance.GetOwnerId()
}

func (manager *SDBInstanceDatabaseManager) AllowListItems(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject) bool {
	if jsonutils.QueryBoolean(query, "admin", false) && !db.IsAllowList(rbacutils.ScopeProject, userCred, manager) {
		return false
	}
	return true
}

func (manager *SDBInstanceDatabaseManager) FetchOwnerId(ctx context.Context, data jsonutils.JSONObject) (mcclient.IIdentityProvider, error) {
	parentId := manager.FetchParentId(ctx, data)
	if len(parentId) > 0 {
		instance, err := db.FetchById(DBInstanceManager, parentId)
		if err != nil {
			return nil, errors.Wrapf(err, "db.FetchById(DBInstanceManager, %s)", parentId)
		}
		return instance.(*SDBInstance).GetOwnerId(), nil
	}
	return db.FetchProjectInfo(ctx, data)
}

func (manager *SDBInstanceDatabaseManager) FilterByOwner(q *sqlchemy.SQuery, userCred mcclient.IIdentityProvider, scope rbacutils.TRbacScope) *sqlchemy.SQuery {
	if userCred != nil {
		sq := DBInstanceManager.Query("id")
		switch scope {
		case rbacutils.ScopeProject:
			sq = sq.Equals("tenant_id", userCred.GetProjectId())
			return q.In("dbinstance_id", sq.SubQuery())
		case rbacutils.ScopeDomain:
			sq = sq.Equals("domain_id", userCred.GetProjectDomainId())
			return q.In("dbinstance_id", sq.SubQuery())
		}
	}
	return q
}

//func (self *SDBInstanceDatabase) AllowUpdateItem(ctx context.Context, userCred mcclient.TokenCredential) bool {
//只能创建或删除，避免update name后造成登录数据库名称异常
//	return false
//}

func (self *SDBInstanceDatabase) ValidateUpdateData(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, data *jsonutils.JSONDict) (*jsonutils.JSONDict, error) {
	return nil, httperrors.ErrForbidden
}

// RDS数据库列表
func (manager *SDBInstanceDatabaseManager) ListItemFilter(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.DBInstanceDatabaseListInput,
) (*sqlchemy.SQuery, error) {
	q, err := manager.SStatusStandaloneResourceBaseManager.ListItemFilter(ctx, q, userCred, query.StatusStandaloneResourceListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SStatusStandaloneResourceBaseManager.ListItemFilter")
	}
	q, err = manager.SExternalizedResourceBaseManager.ListItemFilter(ctx, q, userCred, query.ExternalizedResourceBaseListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SExternalizedResourceBaseManager.ListItemFilter")
	}
	q, err = manager.SDBInstanceResourceBaseManager.ListItemFilter(ctx, q, userCred, query.DBInstanceFilterListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SDBInstanceResourceBaseManager.ListItemFilter")
	}

	if len(query.CharacterSet) > 0 {
		q = q.In("character_set", query.CharacterSet)
	}

	return q, nil
}

func (manager *SDBInstanceDatabaseManager) OrderByExtraFields(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.DBInstanceDatabaseListInput,
) (*sqlchemy.SQuery, error) {
	var err error
	q, err = manager.SStatusStandaloneResourceBaseManager.OrderByExtraFields(ctx, q, userCred, query.StatusStandaloneResourceListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SStatusStandaloneResourceBaseManager.OrderByExtraFields")
	}
	q, err = manager.SDBInstanceResourceBaseManager.OrderByExtraFields(ctx, q, userCred, query.DBInstanceFilterListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SDBInstanceResourceBaseManager.OrderByExtraFields")
	}
	return q, nil
}

func (manager *SDBInstanceDatabaseManager) QueryDistinctExtraField(q *sqlchemy.SQuery, field string) (*sqlchemy.SQuery, error) {
	var err error
	q, err = manager.SStatusStandaloneResourceBaseManager.QueryDistinctExtraField(q, field)
	if err == nil {
		return q, nil
	}
	q, err = manager.SDBInstanceResourceBaseManager.QueryDistinctExtraField(q, field)
	if err == nil {
		return q, nil
	}
	return q, httperrors.ErrNotFound
}

func (self *SDBInstanceDatabase) GetParentId() string {
	return self.DBInstanceId
}

func (manager *SDBInstanceDatabaseManager) FetchParentId(ctx context.Context, data jsonutils.JSONObject) string {
	parentId, _ := data.GetString("dbinstance_id")
	return parentId
}

func (manager *SDBInstanceDatabaseManager) FilterByParentId(q *sqlchemy.SQuery, parentId string) *sqlchemy.SQuery {
	if len(parentId) > 0 {
		q = q.Equals("dbinstance_id", parentId)
	}
	return q
}

func (manager *SDBInstanceDatabaseManager) ValidateCreateData(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, input api.DBInstanceDatabaseCreateInput) (*jsonutils.JSONDict, error) {
	for _, instance := range []string{input.DBInstance, input.DBInstanceId} {
		if len(instance) > 0 {
			input.DBInstance = instance
			break
		}
	}
	if len(input.DBInstance) == 0 {
		return nil, httperrors.NewMissingParameterError("dbinstance")
	}
	_instance, err := DBInstanceManager.FetchByIdOrName(userCred, input.DBInstance)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, httperrors.NewResourceNotFoundError("failed to found dbinstance %s", input.DBInstance)
		}
		return nil, httperrors.NewGeneralError(errors.Wrap(err, "DBInstanceManager.FetchByIdOrName"))
	}
	instance := _instance.(*SDBInstance)
	input.DBInstanceId = instance.Id

	if instance.Status != api.DBINSTANCE_RUNNING {
		return nil, httperrors.NewInputParameterError("DBInstance %s(%s) status is %s require status is %s", instance.Name, instance.Id, instance.Status, api.DBINSTANCE_RUNNING)
	}
	region := instance.GetRegion()
	if region == nil {
		return nil, httperrors.NewInputParameterError("failed to found region for dbinstance %s(%s)", instance.Name, instance.Id)
	}
	for i, _account := range input.Accounts {
		account, err := instance.GetDBInstanceAccount(_account.Account)
		if err != nil {
			return nil, httperrors.NewInputParameterError("failed to found dbinstance %s(%s) account %s: %v", instance.Name, instance.Id, _account.Account, err)
		}
		input.Accounts[i].DBInstanceaccountId = account.Id
	}

	input, err = region.GetDriver().ValidateCreateDBInstanceDatabaseData(ctx, userCred, ownerId, instance, input)
	if err != nil {
		return nil, err
	}

	input.StatusStandaloneResourceCreateInput, err = manager.SStatusStandaloneResourceBaseManager.ValidateCreateData(ctx, userCred, ownerId, query, input.StatusStandaloneResourceCreateInput)
	if err != nil {
		return nil, err
	}

	return input.JSON(input), nil
}

func (self *SDBInstanceDatabase) PostCreate(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, data jsonutils.JSONObject) {
	self.SStatusStandaloneResourceBase.PostCreate(ctx, userCred, ownerId, query, data)
	self.StartDBInstanceDatabaseCreateTask(ctx, userCred, data.(*jsonutils.JSONDict), "")
}

func (self *SDBInstanceDatabase) StartDBInstanceDatabaseCreateTask(ctx context.Context, userCred mcclient.TokenCredential, params *jsonutils.JSONDict, parentTaskId string) error {
	self.SetStatus(userCred, api.DBINSTANCE_DATABASE_CREATING, "")
	task, err := taskman.TaskManager.NewTask(ctx, "DBInstanceDatabaseCreateTask", self, userCred, params, parentTaskId, "", nil)
	if err != nil {
		return errors.Wrap(err, "NewTask")
	}
	task.ScheduleRun(nil)
	return nil
}

func (self *SDBInstanceDatabase) GetDBInstancePrivileges() ([]SDBInstancePrivilege, error) {
	privileges := []SDBInstancePrivilege{}
	q := DBInstancePrivilegeManager.Query().Equals("dbinstancedatabase_id", self.Id)
	err := db.FetchModelObjects(DBInstancePrivilegeManager, q, &privileges)
	if err != nil {
		return nil, err
	}
	return privileges, nil
}

func (self *SDBInstanceDatabase) GetDBInstance() (*SDBInstance, error) {
	instance, err := DBInstanceManager.FetchById(self.DBInstanceId)
	if err != nil {
		return nil, err
	}
	return instance.(*SDBInstance), nil
}

func (self *SDBInstanceDatabase) GetExtraDetails(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, isList bool) (api.DBInstancedatabaseDetails, error) {
	return api.DBInstancedatabaseDetails{}, nil
}

func (manager *SDBInstanceDatabaseManager) FetchCustomizeColumns(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	query jsonutils.JSONObject,
	objs []interface{},
	fields stringutils2.SSortedStrings,
	isList bool,
) []api.DBInstancedatabaseDetails {
	rows := make([]api.DBInstancedatabaseDetails, len(objs))
	stdRows := manager.SStatusStandaloneResourceBaseManager.FetchCustomizeColumns(ctx, userCred, query, objs, fields, isList)
	dbRows := manager.SDBInstanceResourceBaseManager.FetchCustomizeColumns(ctx, userCred, query, objs, fields, isList)
	dbinstanceIds := make([]string, len(objs))
	for i := range rows {
		rows[i] = api.DBInstancedatabaseDetails{
			StatusStandaloneResourceDetails: stdRows[i],
			DBInstanceResourceInfo:          dbRows[i],
		}
		database := objs[i].(*SDBInstanceDatabase)
		rows[i], _ = database.getMoreDetails(ctx, userCred, rows[i])
		dbinstanceIds[i] = database.DBInstanceId
	}

	dbinstances := make(map[string]SDBInstance)
	err := db.FetchStandaloneObjectsByIds(DBInstanceManager, dbinstanceIds, &dbinstances)
	if err != nil {
		log.Errorf("FetchStandaloneObjectsByIds fail: %v", err)
		return rows
	}

	virObjs := make([]interface{}, len(objs))
	for i := range rows {
		if dbinstance, ok := dbinstances[dbinstanceIds[i]]; ok {
			virObjs[i] = &dbinstance
			rows[i].ProjectId = dbinstance.ProjectId
		}
	}

	projRows := DBInstanceManager.SProjectizedResourceBaseManager.FetchCustomizeColumns(ctx, userCred, query, virObjs, fields, isList)
	for i := range rows {
		rows[i].ProjectizedResourceInfo = projRows[i]
	}

	return rows
}

func (self *SDBInstanceDatabase) getPrivilegesDetails() ([]api.DBInstancePrivilege, error) {
	out := []api.DBInstancePrivilege{}
	privileges, err := self.GetDBInstancePrivileges()
	if err != nil {
		return out, errors.Wrap(err, "GetDBInstancePrivileges")
	}
	for _, privilege := range privileges {
		detail, err := privilege.GetPrivilege()
		if err != nil {
			return nil, errors.Wrap(err, "GetDetailedJson")
		}
		out = append(out, detail)
	}
	return out, nil
}

func (self *SDBInstanceDatabase) getMoreDetails(ctx context.Context, userCred mcclient.TokenCredential, out api.DBInstancedatabaseDetails) (api.DBInstancedatabaseDetails, error) {
	privileges, err := self.getPrivilegesDetails()
	if err != nil {
		return out, err
	}
	out.DBInstanceprivileges = privileges
	return out, nil
}

func (manager *SDBInstanceDatabaseManager) SyncDBInstanceDatabases(ctx context.Context, userCred mcclient.TokenCredential, instance *SDBInstance, cloudDatabases []cloudprovider.ICloudDBInstanceDatabase) compare.SyncResult {
	lockman.LockClass(ctx, manager, db.GetLockClassKey(manager, instance.GetOwnerId()))
	defer lockman.ReleaseClass(ctx, manager, db.GetLockClassKey(manager, instance.GetOwnerId()))

	result := compare.SyncResult{}
	dbDatabases, err := instance.GetDBInstanceDatabases()
	if err != nil {
		result.Error(err)
		return result
	}

	removed := make([]SDBInstanceDatabase, 0)
	commondb := make([]SDBInstanceDatabase, 0)
	commonext := make([]cloudprovider.ICloudDBInstanceDatabase, 0)
	added := make([]cloudprovider.ICloudDBInstanceDatabase, 0)
	if err := compare.CompareSets(dbDatabases, cloudDatabases, &removed, &commondb, &commonext, &added); err != nil {
		result.Error(err)
		return result
	}

	for i := 0; i < len(removed); i++ {
		err := removed[i].Purge(ctx, userCred)
		if err != nil {
			result.DeleteError(err)
		} else {
			result.Delete()
		}
	}

	for i := 0; i < len(commondb); i++ {
		err := commondb[i].SyncWithCloudDBInstanceDatabase(ctx, userCred, instance, commonext[i])
		if err != nil {
			result.UpdateError(err)
		} else {
			result.Update()
		}
	}

	for i := 0; i < len(added); i++ {
		err = manager.newFromCloudDBInstanceDatabase(ctx, userCred, instance, added[i])
		if err != nil {
			result.AddError(err)
		} else {
			result.Add()
		}
	}
	return result
}

func (self *SDBInstanceDatabase) SyncWithCloudDBInstanceDatabase(ctx context.Context, userCred mcclient.TokenCredential, instance *SDBInstance, extDatabase cloudprovider.ICloudDBInstanceDatabase) error {
	_, err := db.UpdateWithLock(ctx, self, func() error {
		self.Status = extDatabase.GetStatus()
		self.Name = extDatabase.GetName()
		self.CharacterSet = extDatabase.GetCharacterSet()

		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "SyncWithCloudDBInstanceDatabase.UpdateWithLock")
	}
	return nil
}

func (manager *SDBInstanceDatabaseManager) newFromCloudDBInstanceDatabase(ctx context.Context, userCred mcclient.TokenCredential, instance *SDBInstance, extDatabase cloudprovider.ICloudDBInstanceDatabase) error {
	lockman.LockClass(ctx, manager, db.GetLockClassKey(manager, userCred))
	defer lockman.ReleaseClass(ctx, manager, db.GetLockClassKey(manager, userCred))

	database := SDBInstanceDatabase{}
	database.SetModelManager(manager, &database)

	database.Name = extDatabase.GetName()
	database.DBInstanceId = instance.Id
	database.Status = extDatabase.GetStatus()
	database.CharacterSet = extDatabase.GetCharacterSet()
	database.ExternalId = extDatabase.GetGlobalId()

	err := manager.TableSpec().Insert(ctx, &database)
	if err != nil {
		return errors.Wrapf(err, "newFromCloudDBInstanceDatabase.Insert")
	}
	return nil
}

func (self *SDBInstanceDatabase) Delete(ctx context.Context, userCred mcclient.TokenCredential) error {
	log.Infof("dbinstance database delete do nothing")
	return nil
}

func (self *SDBInstanceDatabase) RealDelete(ctx context.Context, userCred mcclient.TokenCredential) error {
	return self.SStatusStandaloneResourceBase.Delete(ctx, userCred)
}

func (self *SDBInstanceDatabase) CustomizeDelete(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, data jsonutils.JSONObject) error {
	return self.StartDBInstanceDatabaseDeleteTask(ctx, userCred, "")
}

func (self *SDBInstanceDatabase) StartDBInstanceDatabaseDeleteTask(ctx context.Context, userCred mcclient.TokenCredential, parentTaskId string) error {
	self.SetStatus(userCred, api.DBINSTANCE_DATABASE_DELETING, "")
	task, err := taskman.TaskManager.NewTask(ctx, "DBInstanceDatabaseDeleteTask", self, userCred, nil, parentTaskId, "", nil)
	if err != nil {
		return err
	}
	task.ScheduleRun(nil)
	return nil
}

func (manager *SDBInstanceDatabaseManager) ListItemExportKeys(ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	keys stringutils2.SSortedStrings,
) (*sqlchemy.SQuery, error) {
	var err error

	q, err = manager.SStatusStandaloneResourceBaseManager.ListItemExportKeys(ctx, q, userCred, keys)
	if err != nil {
		return nil, errors.Wrap(err, "SStatusStandaloneResourceBaseManager.ListItemExportKeys")
	}
	if keys.ContainsAny(manager.SDBInstanceResourceBaseManager.GetExportKeys()...) {
		q, err = manager.SDBInstanceResourceBaseManager.ListItemExportKeys(ctx, q, userCred, keys)
		if err != nil {
			return nil, errors.Wrap(err, "SDBInstanceResourceBaseManager.ListItemExportKeys")
		}
	}
	return q, nil
}
