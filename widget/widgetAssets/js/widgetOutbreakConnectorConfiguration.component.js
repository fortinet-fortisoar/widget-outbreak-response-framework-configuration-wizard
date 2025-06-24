/* Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end */
'use strict';

(function () {
  let self;
  let configurationSubscription;
  let healtCheckSubscription;
  class widgetOutbreakConnectorConfigurationComponent {
    constructor(websocketService, CommonUtils, DEFAULT_REPO_URL, $filter, currentPermissionsService, $window, fileService, $scope, _, ModalService, connectorService, dataIngestionService, toaster, $timeout, $uibModal, CONNECTOR_CONFIG_EXCLUDE_TAGS, $rootScope, translationService) {
      self = this;
      this.websocketService = websocketService;
      this.CommonUtils = CommonUtils;
      this.DEFAULT_REPO_URL = DEFAULT_REPO_URL;
      this.$filter = $filter;
      this.$rootScope = $rootScope;
      this.$window = $window;
      this.fileService = fileService;
      this.permissions = currentPermissionsService.getPermissions(['agents', 'security', 'connectors']);
      this.isAdmin = currentPermissionsService.isAdmin();
      this.$scope = $scope;
      this.toaster = toaster;
      this.translationService = translationService;
      this.CONNECTOR_CONFIG_EXCLUDE_TAGS = CONNECTOR_CONFIG_EXCLUDE_TAGS;
      this.selectedAgentAllowRemoteOperation = true;
      this._ = _;
      this.formHolder = {};
      this.selected = {
        configuration: null,
        params: {}
      };
      this.input = {
        replace: false,
        selectedConfiguration: '',
        selectionPlaceholder: translationService.instantTranslate('WZ_CONNECTOR.SELECT_CONFIGURATION')
      };
      this.ModalService = ModalService;
      this.connectorService = connectorService;
      this.dataIngestionService = dataIngestionService;
      this.$timeout = $timeout;
      this.$uibModal = $uibModal;
      this.appDatetimeFormat = $rootScope.appDatetimeFormat;
    }

    $onInit() {
      self.connectorInfo = self.contentDetail.connectorInfo;
      self.ingestionButtonTitle = self.translationService.instantTranslate(self.connectorInfo.ingestion_preferences && self.connectorInfo.ingestion_preferences.launch_name ? self.connectorInfo.ingestion_preferences.launch_name : 'CONNECTOR.CONFIGURE_DATA_INGESTION');
      self.hideConfiguration = false;
      self.links = {
        permissionErrorConnectorMsg: self.translationService.injectLinks(
          self.$filter('domPurifySanitize')(self.translationService.instantTranslate('WZ_CONNECTOR.PERMISSION_ERROR_CONNECTOR_CONFIG_INFO', { 'isAdmin': (self.isAdmin), 'isMLEngine': (self.connectorInfo.tags.indexOf('mlengine') !== -1) })),
          'editor/recommendationengine'
        ),
        webserverWarning: self.translationService.injectLinks(
          self.$filter('domPurifySanitize')(self.translationService.instantTranslate('WZ_CONNECTOR.WEBSERVER_CONFIGURED', { 'isAdmin': (self.isAdmin) })),
          'agent-configurations/agents'
        ),
        passwdVaultWarning: self.translationService.injectLinks(
          self.$filter('domPurifySanitize')(self.translationService.instantTranslate('WZ_CONNECTOR.CONFIGURING_PASSWORD_VAULTS', { 'isAdmin': (self.isAdmin) })),
          'security/vault'
        )
      };
      angular.forEach(self.connectorInfo.tags, function (tag) {
        self.hideConfiguration = self.hideConfiguration || self.CONNECTOR_CONFIG_EXCLUDE_TAGS.indexOf(tag) !== -1;
      });
      self.$scope.$on('$destroy', function () {
        if (configurationSubscription) {
          self.websocketService.unsubscribe(configurationSubscription);
        }
        if (healtCheckSubscription) {
          self.websocketService.unsubscribe(healtCheckSubscription);
        }
      });

      self.defaultConfigAvailable = false;
      self.selectedAgentAllowRemoteOperation = true;

      let isConfiguration;
      if (self.connectorInfo && self._.isEmpty(self.connectorInfo.config_schema)) {
        isConfiguration = false;
      } else {
        isConfiguration = true;
      }

      if (self.connectorInfo.status === 'Completed') {
        self.connectorInfo.config_schema.fields = self.$filter('connectorFields')(self.connectorInfo.config_schema.fields);
        self.setNewConfig();
        if (isConfiguration) {
          self.initConfiguration(true);
        }
      }

      self.connectorData = {
        'connector': self.connectorInfo.name,
        'version': self.connectorInfo.version,
        'config': (self.input.configuration ? self.input.configuration.uuid : undefined),
        'configuration': self.input.selectedConfiguration,
        'agent': self.selectedAgent
      };
      self.processing = false;
      self.selected.params = {};
      self.$scope.$on('agent:StatusChanged', function (event, data) {
        if (self.selectedAgent === data.agent) {
          self.input.selectedConfiguration.status = null;
          self.input.selectedConfiguration._message = null;
          self.input.selectedConfiguration.lastKnownHealthTime = undefined;
          self.configHealthAvailable = false;
          self.checkHealth();
        }
      });
    }

    _updateSelectedConfig(update) {
      self.selected.configuration = self.input.selectedConfiguration.id ? self.input.selectedConfiguration : null;
      self.selected.params = {};
      if (update) {
        self._.map(self.connectorInfo.configuration, function (connectorConfig) {
          if (connectorConfig.config_id === self.input.selectedConfiguration.config_id) {
            connectorConfig = self._.extend(connectorConfig, self.input.selectedConfiguration);
          }
        });
      }
    }

    addConfiguration(type) {
      if (type === 'add') {
        self.enableAddConfig = true;
        self.selected.configuration = null;
        self.configurationChanged(null, true);
      } else {
        self.enableAddConfig = false;
        self.initConfiguration();
      }
    }

    //Connector new config
    setNewConfig() {
      if (self.connectorInfo.config_schema) {
        self.connectorInfo.newConfig = {
          fields: self.connectorInfo.config_schema.fields,
          name: '',
          default: self.connectorInfo.configuration.length === 0 ? true : false,
          teams: []
        };
      }
    }

    //subscribe configuration
    subscribeConfiguration() {
      if (configurationSubscription) {
        self.websocketService.unsubscribe(configurationSubscription);
      }
      if (self.selectedAgent && self.input.selectedConfiguration && self.input.selectedConfiguration.config_id) {
        self.websocketService.subscribe('connectorconfiguration/' + self.input.selectedConfiguration.config_id, function (data) {
          if (data.data.status) {
            if (self.input.selectedConfiguration.remote_status) {
              if (self.input.selectedConfiguration.remote_status.status === 'deletion-in-progress' && data.data.status.status === 'finished') {
                var deletedConfig = self._.find(self.connectorInfo.configuration, function (config) {
                  return data.data.data.config_id === config.config_id;
                });
                let index = self.connectorInfo.configuration.indexOf(deletedConfig);
                self.connectorInfo.configuration.splice(index, 1);
                if (self.connectorInfo.configuration.length > 0) {
                  self.input.selectedConfiguration = self.connectorInfo.configuration[0];
                } else {
                  self.configurationChanged(null);
                }
              } else if (self.input.selectedConfiguration.remote_status.status === 'in-progress' && data.data.status.status === 'finished') {
                self.checkHealth();
              }
            }
            self.input.selectedConfiguration.remote_status = data.data.status;
            if (self.configurationData) {
              self.configurationData.status = (data.data.status && (data.data.status === 'in-progress' ? 'configuring' : 'completed')) || 'failed';
            }
            self.toaster.success({
              body: data.data.status.message
            });
          }
        }).then(function (data) {
          configurationSubscription = data;
        });
      } else {
        self.configHealthAvailable = false;
      }
    }

    initConfiguration(status) {
      let defaultConfig;
      if (!self._.isEmpty(self.connectorInfo.configuration)) {
        var configs = [];
        angular.forEach(self.connectorInfo.configuration, function (value, key) {
          var config = {
            name: value.name,
            default: value.default,
            uuid: key,
            config_id: value.config_id,
            id: value.id,
            config: value.config,
            fields: angular.copy(self.connectorInfo.config_schema.fields),
            remote_status: value.remote_status,
            status: value.health_status ? value.health_status.status : {},
            _message: value.health_status ? value.health_status.message : {},
            lastKnownHealthTime: value.health_status ? value.health_status.last_known_health_time : {},
            teams: []
          };
          angular.forEach(value.teams, function (team) {
            var assignedTeams = self._.find(self.owners, function (owner) {
              return self.$filter('getEndPathName')(owner['@id']) === team;
            });
            if (assignedTeams) {
              config.teams.push(assignedTeams);
              config.isVisible = true;
            }
          });
          config.fields = self.$filter('connectorFields')(config.fields);
          self.populateValues(config.fields, value.config);
          configs.push(config);
          if (config.default) {
            defaultConfig = config;
          }
        });
        self.connectorInfo.configuration = configs;
        self.input.selectedConfiguration = defaultConfig ? defaultConfig : self.connectorInfo.configuration[0];
      } else {
        self.connectorInfo.configuration = [];
        self.input.selectedConfiguration = angular.copy(self.connectorInfo.newConfig);
      }
      self._updateSelectedConfig();
      self.checkHealth(status);
      self.input.oldSelectedConfiguration = angular.copy(self.input.selectedConfiguration);
      self.subscribeConfiguration();
    }

    removeDefaultFromOthers() {
      if (self.input.selectedConfiguration && self.input.selectedConfiguration.config_id) {
        angular.forEach(self.connectorInfo.configuration, function (configuration) {
          if (configuration.config_id !== self.input.selectedConfiguration.config_id) {
            configuration.default = false;
          }
        });
      }
    }

    checkHealth(ingestionStatus) {
      if (!self.input.selectedConfiguration || self.input.selectedConfiguration.name === '') {
        return;
      }
      self.healthCheckProcessing = true;
      self.connectorService.getConnectorHealth(self.connectorInfo, self.input.selectedConfiguration.config_id, self.selectedAgent).then(function (data) {
        if (data.id) {//contains id means it is the return call for agent health check
          self.websocketService.subscribe(data.id, function (result) {
            if (result.status && (result.status === 'Available' || result.status === 'Disconnected' || result.status === 'Deactivated')) {
              self.$rootScope.$broadcast('healthCheckDetails', { 'tabIndex': self.tabIndex, 'config_id': result.config_id, 'connectorInfo': self.connectorInfo });
              var updateConfig = self._.find(self.connectorInfo.configuration, function (config) {
                return config.config_id === result.config_id;
              });
              if (updateConfig) {
                updateConfig.status = result.status;
                updateConfig._message = result.message;
                updateConfig.lastKnownHealthTime = result.last_known_health_time;
                self.input.selectedConfiguration.status = result.status;
                self.input.selectedConfiguration._message = result.message;
                self.input.selectedConfiguration.lastKnownHealthTime = result.last_known_health_time;
              }
            }
            self.healthCheckProcessing = false;
            self.websocketService.unsubscribe(healtCheckSubscription);
          }).then(function (sub) {
            healtCheckSubscription = sub;
          });
        } else {
          self.healthCheckProcessing = false;
          self.input.selectedConfiguration.status = data.status;
          self.input.selectedConfiguration._message = data.message;
          self.connectorInfo.configuration.forEach(function (config) {
            if (config.config_id === data.config_id) {
              config.status = data.status;
            }
          });
          self.input.selectedConfiguration.lastKnownHealthTime = undefined;
          self.$rootScope.$broadcast('healthCheckDetails', { 'tabIndex': self.tabIndex, 'config_id': data.config_id, 'connectorInfo': self.connectorInfo });
        }
      }, function (error) {
        self.input.selectedConfiguration.status = error.data.status || null;
        self.input.selectedConfiguration._message = self.translationService.instantTranslate('WZ_CONNECTOR.HEALTH_CHECK_FAILED') + ' :' + error.data.message;
        self.healthCheckProcessing = false;
        self.toaster.error({
          body: error.data.message
        });
      });
    }

    removeConfiguration(configurationObj) {
      if (configurationObj) {
        var index;
        angular.forEach(self.connectorInfo.configuration, function (config, key) {
          if (config.config_id === configurationObj.config_id) {
            index = key;
          }
        });
        if (index >= 0) {
          var message = self.translationService.instantTranslate('WZ_CONNECTOR.MODAL_CONFIRM_REMOVE_CONFIGURATION');
          self.ModalService.confirm(message).then(function (result) {
            if (!result) {
              return;
            }
            if (self.selectedAgent) {
              self.saveConfiguration('deleteConfigAndSave', true);
            } else {
              self.connectorInfo.configuration.splice(index, 1);
              self.input.selectedConfiguration = configurationObj;
              self.saveConfiguration('deleteConfigAndSave', true);
              if (self.connectorInfo.configuration.length > 0) {
                self.input.selectedConfiguration = self.connectorInfo.configuration[0];
              } else {
                self.configurationChanged(null);
              }
              self._updateSelectedConfig();
            }
          });
        }
      }
    }

    configurationChanged(configuration, enableAddConfig) {
      self.$rootScope.$broadcast('configurationChanged', { 'tabIndex': self.tabIndex, 'configuration': configuration });
      self.formHolder.connectorForm[self.tabIndex].$setPristine();
      self.input.selectedConfiguration = configuration;
      self.selected.params = {};
      if (self.input.oldSelectedConfiguration.uuid && !self.validateConfigurationForm()) {
        self.input.selectedConfiguration = self.input.oldSelectedConfiguration;
        return;
      }
      if (self.CommonUtils.isUndefined(self.connectorInfo)) {
        return;
      }
      if (self.CommonUtils.isUndefined(configuration)) {
        let newConfigObject = angular.copy(self.connectorInfo.newConfig);
        newConfigObject.default = false;
        self.input.selectedConfiguration = newConfigObject;
      }
      self._updateSelectedConfig();
      if (!enableAddConfig) {
        self.enableAddConfig = false;
      }
      if (!self.selectedAgent) {
        self.checkHealth(status);
      }
      self.input.oldSelectedConfiguration = angular.copy(self.input.selectedConfiguration);
      self.subscribeConfiguration();
    }

    populateValues(parameters, value) {
      angular.forEach(parameters, function (parameter) {
        parameter.value = value[parameter.name];
        if (parameter.onchange) {
          if (parameter.type === 'multiselect' && angular.isArray(parameter.value)) {
            parameter.value.forEach(function (selected) {
              if (parameter.onchange[selected]) {
                self.populateValues(parameter.onchange[selected], value);
              }
            });
          } else if (parameter.onchange[parameter.value]) {
            self.populateValues(parameter.onchange[parameter.value], value);
          }
        }
      });
    }

    //save configurations
    saveConfiguration(saveFrom, removeConfiguration, progressStatus) {
      let data = angular.copy(self.connectorInfo);
      let newConfiguration, newConfig, deleteConfig;
      newConfiguration = false;
      if (saveFrom !== 'deleteConfigAndSave') {
        if (!self._.isEmpty(self.connectorInfo.config_schema)) {
          if (!self.validateConfigurationForm()) {
            return;
          }
        }
        if (!self.input.selectedConfiguration.id) {
          newConfiguration = true;
          self.input.selectedConfiguration.config_id = self.$window.UUID.generate();
          if (self.input.selectedConfiguration.default) {
            angular.forEach(data.configuration, function (configuration) {
              if (configuration.config_id !== self.input.selectedConfiguration.config_id) {
                configuration.default = false;
              }
            });
          }
          data.configuration.push(self.input.selectedConfiguration);
          newConfig = self.input.selectedConfiguration;
          self.subscribeConfiguration();
        }
        delete data.newConfig;
      }

      if (saveFrom === 'deleteConfigAndSave') {
        deleteConfig = true;
      }

      self.configurationData = {
        connector: data.label,
        connector_version: data.version,
        label: self.input.selectedConfiguration.name,
        message: '',
        status: 'configuring'
      };

      if (progressStatus !== 'reload' && saveFrom !== 'deleteConfigAndSave') {
        self.$uibModal.open({
          templateUrl: 'app/connector/connectorConfigProgress.component.html',
          backdrop: 'static',
          scope: self.$scope,
          size: 'md',
          controller: ['$scope', '$uibModalInstance', function ($scope, $uibModalInstance) {
            $scope.exitConfigProgressModal = function () {
              $uibModalInstance.close();
            };
          }]
        });
      }

      var updateData = {
        connector: data.id,
        connector_name: data.name,
        connector_version: data.version,
        name: self.input.selectedConfiguration.name,
        config_id: self.input.selectedConfiguration.config_id,
        id: self.input.selectedConfiguration.id,
        default: self.input.selectedConfiguration.default,
        config: {},
        teams: self.input.selectedConfiguration.teams
      };
      if (self.selectedAgent) {
        updateData.agent = self.selectedAgent;
      }
      self.saveValues(self.input.selectedConfiguration.fields, updateData.config);
      if (removeConfiguration) {
        self.removeConfProcessing = true;
      } else {
        self.saveProcessing = true;
      }
      self.connectorService.updateConnectorConfig(updateData, newConfiguration, deleteConfig).then(function (response) {
        if (!self.selectedAgent) {
          if (saveFrom === 'deleteConfigAndSave') {
            self.toaster.success({
              body: self.translationService.instantTranslate('WZ_CONNECTOR.TOASTER_SUCCESS_CONNECTOR_UPDATED', { 'label': self.connectorInfo.label })
            });
          } else {
            self.configurationData.status = 'completed';
          }
        }
        if (newConfig) {
          response.fields = newConfig.fields;
          self.connectorInfo.configuration.push(response);
          if (newConfig.default) {
            self.removeDefaultFromOthers();
          }
        }

        self.formHolder.connectorForm[self.tabIndex].$setPristine();
        if (!deleteConfig) {
          self.input.selectedConfiguration.id = response.id;
          delete self.input.selectedConfiguration.status;
          if (!newConfig) {
            self._updateSelectedConfig(true);
          } else {
            self._updateSelectedConfig();
          }
        }
        if (self.selectedAgent) {
          if (newConfig) {
            newConfig.remote_status = response.remote_status;
          } else {
            self.input.selectedConfiguration.remote_status = response.remote_status;
          }
          self.configurationData.status = (response.remote_status && (response.remote_status.status === 'in-progress' ? 'configuring' : 'completed')) || 'failed';
        } else {
          self.checkHealth(true);
        }
        self.enableAddConfig = false;
      }, function (error) {
        if (saveFrom === 'deleteConfigAndSave') {
          self.$timeout(function () {
            self.toaster.error({
              body: error.data.message || error.data
            });
          }, 10);
        } else {
          self.configurationData.message = error.data.message || error.data;
          self.configurationData.status = 'failed';
        }
      }).finally(function () {
        if (removeConfiguration) {
          self.removeConfProcessing = false;
        } else {
          self.saveProcessing = false;
        }
      });
    }

    validateConfigurationForm() {
      if (self.formHolder.connectorForm[self.tabIndex] && !self.formHolder.connectorForm[self.tabIndex].$valid) {
        self.toaster.error({
          body: self.translationService.instantTranslate('WZ_CONNECTOR.TOASTER_ERROR_FIX_ERROR')
        });
        self.formHolder.connectorForm[self.tabIndex].$setTouched();
        self.formHolder.connectorForm[self.tabIndex].$focusOnFirstError();
        return false;
      }
      return true;
    }

    saveValues(parameters, config) {
      angular.forEach(parameters, function (parameter) {
        config[parameter.name] = self.CommonUtils.isUndefined(parameter.value) ? '' : parameter.value;
        if (parameter.parameters) {//nested fields
          self.saveValues(parameter.parameters, config);
        }
      });
    }

    toggleAgentMode(agentMode) {
      self.$rootScope.$broadcast('toggleAgentMode', { 'tabIndex': self.tabIndex, 'agentMode': agentMode });
      self.formHolder.connectorForm[self.tabIndex].$setPristine();
      self.agentMode = agentMode;
      if (agentMode) {
        self.connectorService.getAgents(self.connectorInfo).then(function (agents) {
          if (agents.length > 0) {
            self.agentChanged(agents[0].agent);
          }
          self.configuredAgents = agents;
        });
      } else {
        self.selectedAgent = undefined;
        self.agentChanged();
      }
    }

    agentChanged(agent) {
      self.selectedAgent = agent;
      if (self.selectedAgent) {
        let selectedAgentObject = self._.find(self.configuredAgents, function (a) { return a.agent === self.selectedAgent; });
        self.selectedAgentIncompatibility = selectedAgentObject.isIncompatible;
        self.selectedAgentAllowRemoteOperation = selectedAgentObject.allow_remote_operation;
      } else {
        self.selectedAgentIncompatibility = false;
        self.selectedAgentAllowRemoteOperation = true;
      }
      self.connectorService.getConnector(self.connectorInfo.name, self.connectorInfo.version, self.selectedAgent).then(function (connector) {
        self.connectorInfo.configuration = connector.configuration;
        if (!self.connectorInfo.selfVersion) {
          self.connectorInfo.selfVersion = self.connectorInfo.version;
        }
        self.connectorInfo.version = connector.version;
        self.connectorInfo.id = connector.id;
        self.connectorInfo.config_schema = connector.config_schema;
        self.initConfiguration();
      });
    }

    installDependencies() {
      self.retryProcessing = true;
      let agentID;
      if (self.connectorInfo && self.connectorInfo.agent) {
        agentID = self.connectorInfo.agent;
      }
      self.connectorService.installDependencies(self.connectorInfo, agentID).then(function () {
        self.contentDetail.requirements_installed = 'Completed';
        self.retryProcessing = false;
        self.saveConfiguration('', false, 'reload');
      }, function () {
        self.retryProcessing = false;
      });
    }
  }

  angular.module('cybersponse').component('widgetOutbreakConnectorConfigurationComponent', {
    bindings: {
      contentDetail: '<',
      closePanel: '&',
      owners: '<',
      tabIndex: '<',
      configuredAgents: '<'
    },
    controller: ['websocketService', 'CommonUtils', 'DEFAULT_REPO_URL', '$filter', 'currentPermissionsService', '$window', 'fileService', '$scope', '_', 'ModalService', 'connectorService', 'dataIngestionService', 'toaster', '$timeout', '$uibModal', 'CONNECTOR_CONFIG_EXCLUDE_TAGS', '$rootScope', 'translationService',
      widgetOutbreakConnectorConfigurationComponent,
    ],
    templateUrl: 'widgets/installed/outbreakAlertConfiguration-2.2.0/widgetAssets/html/widgetOutbreakConnectorConfiguration.component.html'
  });
})();