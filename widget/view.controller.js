/* Copyright start
  MIT License
  Copyright (c) 2025 Fortinet Inc
  Copyright end */
'use strict';
(function () {
    angular
        .module('cybersponse')
        .controller('outbreakAlertConfiguration220Ctrl', outbreakAlertConfiguration220Ctrl);

    outbreakAlertConfiguration220Ctrl.$inject = ['$scope', '$http', 'WizardHandler', '$controller', '$state', 'connectorService', 'marketplaceService', 'CommonUtils', '$window', 'toaster', 'currentPermissionsService', '_', '$resource', 'API', 'ALL_RECORDS_SIZE', 'widgetBasePath', '$rootScope', 'websocketService', '$timeout', 'widgetUtilityService', 'PagedCollection', 'Query'];

    function outbreakAlertConfiguration220Ctrl($scope, $http, WizardHandler, $controller, $state, connectorService, marketplaceService, CommonUtils, $window, toaster, currentPermissionsService, _, $resource, API, ALL_RECORDS_SIZE, widgetBasePath, $rootScope, websocketService, $timeout, widgetUtilityService, PagedCollection, Query) {
        $controller('BaseConnectorCtrl', {
            $scope: $scope
        });
        $scope.processingPicklist = false;
        $scope.huntparams = {};
        $scope.isConnectorsHealthy = false;
        $scope.processingConnector = false;
        $scope.selectHuntTool = selectHuntTool;
        $scope.triggerAutoInstallOutbreaksPlaybook = triggerAutoInstallOutbreaksPlaybook;
        $scope.backStartPage = backStartPage;
        $scope.configHuntTool = configHuntTool;
        $scope.onlyNumbers = '^(?:[1-9]|[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|360|361|362|363|364|365)$';
        $scope.onlyPositivenumbers = '^[1-9][0-9]*$';
        $scope.backSelectHuntTools = backSelectHuntTools;
        $scope.threatHuntSchedule = threatHuntSchedule;
        $scope.backThreatHuntConfig = backThreatHuntConfig;
        $scope.backThreatHuntSchedule = backThreatHuntSchedule;
        $scope.cancel = cancel;
        $scope.moveToFinish = moveToFinish;
        $scope.close = close;
        $scope.saveConnector = saveConnector;
        $scope.getDisplayHuntTools = getDisplayHuntTools;
        $scope.threatHuntConfigurationChanged = threatHuntConfigurationChanged;
        $scope.loadActiveTab = loadActiveTab;
        $scope.toggle = [];
        $scope.configPlaybookTaskID = '';
        $scope.toggleRemediation = true;
        $scope.toggleConnectorConfig = [];
        $scope.connectorHealthStatus = [];
        $scope.connectorDefaultStatus = [];
        $scope.toggleRemediationConfig = false;
        $scope.isPlaybookExecuted = false;
        $scope.toggleAdvancedSettings = toggleAdvancedSettings;
        $scope.toggleConnectorConfigSettings = toggleConnectorConfigSettings;
        $scope.backNotification = backNotification;
        $scope.nextNotification = nextNotification;
        $scope.isLightTheme = $rootScope.theme.id === 'light';
        $scope.widgetBasePath = widgetBasePath;
        $scope.startInfoGraphics = $scope.isLightTheme ? widgetBasePath + 'images/start-light.svg' : widgetBasePath + 'images/start-dark.svg';
        $scope.selectThreadHuntTool = $scope.isLightTheme ? widgetBasePath + 'images/select-threat-hunt-tool-light.svg' : widgetBasePath + 'images/select-threat-hunt-tool-dark.svg';
        $scope.threatHuntToolConfig = $scope.isLightTheme ? widgetBasePath + 'images/threat-hunt-config-light.svg' : widgetBasePath + 'images/threat-hunt-config-dark.svg';
        $scope.outbreakSettings = $scope.isLightTheme ? widgetBasePath + 'images/remediation-light.svg' : widgetBasePath + 'images/remediation-dark.svg';
        $scope.threatTuntSchedule = $scope.isLightTheme ? widgetBasePath + 'images/threat-hunt-schedule-light.svg' : widgetBasePath + 'images/threat-hunt-schedule-dark.svg';
        $scope.finishInfoGraphics = widgetBasePath + 'images/finish.png';
        $scope.widgetCSS = widgetBasePath + 'widgetAssets/css/wizard-style.css';
        $scope.params = { activeTab: 0 };
        $scope.noDefaultConnectorSelected = false;
        const nistConnectorName = 'NIST National Vulnerability Database';
        $scope.ingestionDetails = {
            "name": "Outbreak-Alerts",
            "playbook_uuid": "70d2c10e-50d4-43ce-b606-0f0d0d305fad"
        }
        $scope.selected = {
            configuration: null,
            params: {}
        };
        $controller('BaseConnectorCtrl', {
            $scope: $scope
        });
        $scope.selectedEnv = {
            huntTools: [],
            threatHuntToolsParams: {
                fazParams: null,
                fsmParams: null,
                qRadarParams: null,
                splunkParams: null
            },
            timeFrameDays: null,
            emailAddress: null,
            scheduleFrequency: null,
            autoInstallOutbreaks: {
                installSelectedOutbreaks: true,
                installOutbreaksFromLastXDays: 0,
                installOutbreakType: []
            }
        };
        $scope.outbreakAlertSeverityList = ['Critical', 'High', 'Medium'];

        $scope.parent_wf_id = '';
        var subscription;

        $scope.$on('websocket:reconnect', function () {
            initWebsocket();
        });

        function initWebsocket() {
            websocketService.subscribe('runningworkflow', function (data) {
                if (data.parent_wf === 'null' && $scope.isPlaybookExecuted === false) {
                    $scope.isPlaybookExecuted = true;
                    $scope.parent_wf_id = data.instance_ids;
                }
                //do nothing in case of notification recieved from same websocketSession. As it is handled gracefully.
                if (data.sourceWebsocketId !== websocketService.getWebsocketSessionId()) {
                    if ($scope.taskId && data.task_id && data.task_id === $scope.taskId && data.parent_wf === 'null') {
                        $scope.taskId = undefined;
                    }
                }
                if ((data.status === 'failed' || data.status === 'finished with error' || data.status === 'finished') && $scope.configPlaybookTaskID === data.task_id) {
                    getPlaybookResult();
                }
            }).then(function (data) {
                subscription = data;
            });
        }

        $scope.$on('$destroy', function () {
            if (subscription) {
                // Unsubscribe
                websocketService.unsubscribe(subscription);
            }
        });

        function getPlaybookResult() {
            var endpoint = API.WORKFLOW + 'api/workflows/' + $scope.parent_wf_id + '/';
            $http.get(endpoint).then(function (response) {
                if (response.data.status === 'finished' || response.data.status === 'finished with error') {
                    WizardHandler.wizard('OutbreaksolutionpackWizard').next();
                    getDisplayHuntTools();
                }
                $scope.isPlaybookExecuted = false;
            });
        }

        $scope.$on('scheduleDetails', function (event, data) {
            $scope.scheduleStatus = data.status;
            $scope.scheduleID = data.scheduleId;
            $scope.selectedEnv.scheduleFrequency = data.scheduleFrequency;
        });

        function toggleAdvancedSettings(index) {
            $scope.toggle[index] = !$scope.toggle[index];
        }

        function toggleConnectorConfigSettings(index) {
            $scope.toggleConnectorConfig[index] = !$scope.toggleConnectorConfig[index];
        }

        function loadActiveTab(tabIndex, tabName) {
            if (CommonUtils.isUndefined(tabIndex)) {
                var selectedHuntTool = $scope.selectedEnv.huntTools[0];
                var huntToolName = _.get($scope.huntToolsMapping, selectedHuntTool);
                if (CommonUtils.isUndefined($scope.params.activeTab)) {
                    $scope.params = {
                        activeTab: 0
                    }
                }
                _fetchConnectorConfig(huntToolName, $scope.params.activeTab);


            }
            else {
                var huntToolName = _.get($scope.huntToolsMapping, tabName);
                _fetchConnectorConfig(huntToolName, tabIndex);
            }
        }

        function _activeErrorTab(tabName, tabIndex) {
            $scope.params.activeTab = CommonUtils.isUndefined(tabIndex) ? 0 : tabIndex;
            if (CommonUtils.getObjectLength($scope.huntparams) === 0) {
                var formParams = {};
                for (let key in $scope.formHolder.connectorForm[tabIndex].$$parentForm) {
                    if (!key.startsWith("$") && key.indexOf('.') === -1) {
                        formParams[key] = $scope.formHolder.connectorForm[tabIndex].$$parentForm[key];
                        for (let k in formParams[key]) {
                            if (!k.startsWith("$") && k.indexOf('.') === -1) {
                                $scope.huntparams[k] = formParams[key][k];
                            }
                        }
                    }
                }
            }
            for (let k in $scope.huntparams) {
                if ($scope.huntparams[k].$valid === false) {
                    $scope.huntparams[k].$touched = true;
                    $scope.huntparams[k].$invalid = true;
                }
            }
        }

        function configHuntTool() {
            var queryBody = {
                "logic": "AND",
                "filters": [
                    {
                        "type": "primitive",
                        "field": "key",
                        "value": "outbreak-threat-hunt-tools-params",
                        "operator": "eq",
                        "_operator": "eq"
                    }
                ]
            };
            var queryString = {
                $limit: ALL_RECORDS_SIZE
            };
            $resource(API.QUERY + 'keys').save(queryString, queryBody).$promise.then(function (response) {
                if (response['hydra:member'] && response['hydra:member'].length > 0) {
                    if ($scope.selectedEnv.huntTools[0] !== nistConnectorName) {
                        $scope.selectedEnv.huntTools.splice(0, 0, nistConnectorName);
                    }
                    $scope.toggle = [];
                    $scope.toggleConnectorConfig = [];
                    $scope.connectorHealthStatus = [];
                    $scope.connectorDefaultStatus = [];
                    $scope.threatHuntToolsParams = response['hydra:member'][0].jSONValue;
                    for (let index = 0; index < $scope.selectedEnv.huntTools.length; index++) {
                        $scope.toggle[index] = false;
                        $scope.toggleConnectorConfig[index] = true;
                        $scope.connectorHealthStatus[index] = false;
                        $scope.connectorDefaultStatus[index] = true;

                    }
                    loadActiveTab($state.params.tabIndex, $state.params.tab);
                    WizardHandler.wizard('OutbreaksolutionpackWizard').next();
                }
                else {
                    toaster.error({
                        body: 'Threat Hunt Tool parameters is not found in Key-Store'
                    });
                    return;
                }
            });
        }

        function close() {
            $timeout(function () { $window.location.reload(); }, 3000);
            $state.go('main.modules.list', { module: 'outbreak_alerts' }, { reload: true });
            $scope.$parent.$parent.$parent.$ctrl.handleClose();
        }

        function selectHuntTool() {
            $scope.processingPicklist = true;
            var queryBody = {
                "logic": "AND",
                "filters": [
                    {
                        "type": "primitive",
                        "field": "key",
                        "value": "outbreak-threat-hunt-tools",
                        "operator": "eq",
                        "_operator": "eq"
                    }
                ]
            };
            var queryString = {
                $limit: ALL_RECORDS_SIZE
            };
            $resource(API.QUERY + 'keys').save(queryString, queryBody).$promise.then(function (response) {
                if (response['hydra:member'] && response['hydra:member'].length > 0) {
                    $scope.processingPicklist = false;
                    $scope.huntToolsMapping = response['hydra:member'][0].jSONValue;
                    $scope.threatHuntTools = Object.keys($scope.huntToolsMapping).sort();
                    let index = $scope.threatHuntTools.indexOf(nistConnectorName);
                    if (index !== -1) {
                        $scope.threatHuntTools.splice(index, 1);
                    }
                    WizardHandler.wizard('OutbreaksolutionpackWizard').next();
                }
                else {
                    toaster.error({
                        body: 'Threat Hunt Tool is not found in Key-Store'
                    });
                    return;
                }
            });

        }

        function _fetchConnectorConfig(connectorName, tabIndex) {
            var queryBody = {
                "logic": "AND",
                "filters": [
                    {
                        "field": "name",
                        "operator": "in",
                        "value": connectorName
                    }
                ]
            };
            $resource(API.QUERY + 'solutionpacks').save({ $limit: ALL_RECORDS_SIZE }, queryBody).$promise
                .then(function (response) {
                    if (Array.isArray(response['hydra:member']) && response['hydra:member'].length > 0) {
                        var huntToolDetails = _.map(response['hydra:member'], obj => {
                            return _.pick(obj, ['name', 'label', 'version', 'uuid']);
                        });

                        if (huntToolDetails.length > 0) {
                            _loadConnectorDetails(huntToolDetails[0].name, huntToolDetails[0].version, huntToolDetails[0], tabIndex);
                        } else {
                            console.error('No hunt tool details available');
                        }
                    } else {
                        console.error('No data found in response[\'hydra:member\']');
                    }
                })
                .catch(function (error) {
                    console.error('An error occurred:', error);
                });
        }

        function _loadConnectorDetails(connectorName, connectorVersion, sourceControl, tabIndex) {
            $scope.processingConnector = true;
            $scope.configuredConnector = false;
            $scope.isConnectorHealthy = false;
            connectorService.getConnector(connectorName, connectorVersion).then(function (connector) {
                marketplaceService.getContentDetails(API.BASE + 'solutionpacks/' + sourceControl.uuid + '?$relationships=true').then(function (response) {
                    $scope.contentDetail = response.data;
                    if (connector.configuration.length > 0) {
                        $scope.isConnectorConfigured = true;
                        connectorService.getConnectorHealth(response.data, connector.configuration[0].config_id, connector.configuration[0].agent).then(function (data) {
                            if (data.status === "Available") {
                                $scope.isConnectorHealthy = true;
                            }
                        });
                    }
                    else {
                        $scope.isConnectorConfigured = false;
                    }
                });
                if (!connector) {
                    toaster.error({
                        body: 'The Connector "' + connectorName + '" is not installed. Install the connector and re-run this wizard to complete the configuration'
                    });
                    return;
                }
                $scope.selectedConnector = connector;
                $scope.loadConnector($scope.selectedConnector, false, false);
                $scope.processingConnector = false;
            });
        }

        function saveConnector(tabIndex, saveFrom) {
            $scope.isConnectorConfigured = true;
            $scope.configuredConnector = false;
            var data = angular.copy($scope.connector);
            if (CommonUtils.isUndefined(data)) {
                $scope.statusChanged = false;
                return;
            }
            if (!currentPermissionsService.availablePermission('connectors', 'update')) {
                $scope.statusChanged = false;
                return;
            }
            var newConfiguration, newConfig, deleteConfig;
            newConfiguration = false;
            if (saveFrom !== 'deleteConfigAndSave') {
                if (!_.isEmpty($scope.connector.config_schema)) {
                    if (!validateConfigurationForm(tabIndex)) {
                        return;
                    }
                }
                if (!$scope.input.selectedConfiguration.id) {
                    newConfiguration = true;
                    $scope.input.selectedConfiguration.config_id = $window.UUID.generate();
                    if ($scope.input.selectedConfiguration.default) {
                        angular.forEach(data.configuration, function (configuration) {
                            if (configuration.config_id !== $scope.input.selectedConfiguration.config_id) {
                                configuration.default = false;
                            }
                        });
                    }
                    data.configuration.push($scope.input.selectedConfiguration);
                    newConfig = $scope.input.selectedConfiguration;
                }
                delete data.newConfig;
            }
            if (saveFrom === 'deleteConfigAndSave') {
                $scope.isConnectorConfigured = false;
                deleteConfig = true;
                $scope.isConnectorHealthy = false;
            }
            var updateData = {
                connector: data.id,
                name: $scope.input.selectedConfiguration.name,
                config_id: $scope.input.selectedConfiguration.config_id,
                id: $scope.input.selectedConfiguration.id,
                default: $scope.input.selectedConfiguration.default,
                config: {},
                teams: $scope.input.selectedConfiguration.teams
            };
            $scope.saveValues($scope.input.selectedConfiguration.fields, updateData.config);
            $scope.processing = true;
            connectorService.updateConnectorConfig(updateData, newConfiguration, deleteConfig).then(function (response) {
                if (newConfig) {
                    $scope.connector.configuration.push(response);
                    if (newConfig.default) {
                        $scope.removeDefaultFromOthers();
                    }
                }
                $scope.formHolder.connectorForm[tabIndex].$setPristine();
                if (!deleteConfig) {
                    $scope.input.selectedConfiguration.id = response.id;
                    $scope.configuredConnector = true;
                    $scope.isConnectorHealthy = true;
                }
                $scope.checkHealth();
                $scope.statusChanged = false;
            }, function (error) {
                toaster.error({
                    body: error.data.message ? error.data.message : error.data['hydra:description']
                });
            }).finally(function () {
                $scope.processing = false;
            });
        }

        function validateConfigurationForm(tabIndex) {
            if ($scope.formHolder.connectorForm[tabIndex] && !$scope.formHolder.connectorForm[tabIndex].$valid) {
                toaster.error({
                    body: 'Please fix the highlighted errors.'
                });
                $scope.formHolder.connectorForm[tabIndex].$setTouched();
                $scope.formHolder.connectorForm[tabIndex].$focusOnFirstError();
                return false;
            }
            return true;
        }

        function threatHuntConfigurationChanged(tabIndex, configuration, enableAddConfig) {
            $scope.formHolder.connectorForm[tabIndex].$setPristine();
            $scope.input.selectedConfiguration = configuration;
            $scope.selected.params = {};
            if ($scope.input.oldSelectedConfiguration.uuid && !validateConfigurationForm(tabIndex)) {
                $scope.input.selectedConfiguration = $scope.input.oldSelectedConfiguration;
                return;
            }
            if (CommonUtils.isUndefined($scope.connector)) {
                return;
            }
            if (CommonUtils.isUndefined(configuration)) {
                let newConfigObject = angular.copy($scope.connector.newConfig);
                newConfigObject.default = false;
                $scope.input.selectedConfiguration = newConfigObject;
            }
            _updateSelectedConfig();
            if (!enableAddConfig) {
                $scope.enableAddConfig = false;
            }
            if (!$scope.selectedAgent) {
                $scope.checkHealth(status);
            } else {
                $scope.checkIngestionEnable();
            }
            if ($scope.connector.configuration.length === 0) {
                $scope.input.selectedConfiguration.default = true;
            }
            else {
                let isDefault = false;
                ($scope.connector.configuration).forEach(config => {
                    if (config.default) {
                        isDefault = true;
                    }
                });
                if (!isDefault && CommonUtils.isUndefined($scope.selected.configuration)) {
                    $scope.input.selectedConfiguration.default = true;
                }
            }
            $scope.input.oldSelectedConfiguration = angular.copy($scope.input.selectedConfiguration);
        }

        function _updateSelectedConfig(update) {
            $scope.selected.configuration = $scope.input.selectedConfiguration.id ? $scope.input.selectedConfiguration : null;
            $scope.selected.params = {};
            if (update) {
                _.map(self.connector.configuration, function (connectorConfig) {
                    if (connectorConfig.config_id === $scope.input.selectedConfiguration.config_id) {
                        connectorConfig = self._.extend(connectorConfig, $scope.input.selectedConfiguration);
                    }
                });
            }
        }

        function backNotification() {
            WizardHandler.wizard('OutbreaksolutionpackWizard').previous();
        }

        function nextNotification(threatHuntConfigForm) {
            if (!CommonUtils.isUndefined(threatHuntConfigForm.fazForm) && threatHuntConfigForm.fazForm.$invalid) {
                _connectorErrorHandling('Fortinet FortiAnalyzer');
                return;
            } else if (!CommonUtils.isUndefined(threatHuntConfigForm.fsmForm) && threatHuntConfigForm.fsmForm.$invalid) {
                _connectorErrorHandling('SpFortinet FortiSIEMlunk');
                return
            }
            else if (!CommonUtils.isUndefined(threatHuntConfigForm.qradarForm) && threatHuntConfigForm.qradarForm.$invalid) {
                _connectorErrorHandling('IBM QRadar');
                return;
            } else if (!CommonUtils.isUndefined(threatHuntConfigForm.splunkForm) && threatHuntConfigForm.splunkForm.$invalid) {
                _connectorErrorHandling('Splunk');
                return;
            } else {
                _checkConnectorHealth();
            }

        }

        function _connectorErrorHandling(threatHuntTool) {
            var huntToolIndex = $scope.selectedEnv.huntTools.indexOf(threatHuntTool);
            _activeErrorTab(threatHuntTool, huntToolIndex);
            loadActiveTab(huntToolIndex, threatHuntTool);
            var paramsConfig = document.getElementById('accordion-params-config-' + huntToolIndex);
            paramsConfig.childNodes[2].classList.add('in');
            toggleAdvancedSettings(huntToolIndex);
            var connectorConfig = document.getElementById('accordion-connector-config-' + huntToolIndex);
            connectorConfig.childNodes[2].classList.replace('in', null);
            toggleConnectorConfigSettings(huntToolIndex);
            toaster.error({
                body: threatHuntTool + ' Threat Hunt Tool parameters are required'
            });
        }

        function _checkConnectorHealth() {
            $scope.isConnectorsHealthy = true;
            // Array to hold all promises
            let promises = [];
            for (let index = 0; index < $scope.selectedEnv.huntTools.length; index++) {
                let huntToolName = _.get($scope.huntToolsMapping, $scope.selectedEnv.huntTools[index]);
                let queryBody = {
                    "logic": "AND",
                    "filters": [
                        {
                            "field": "name",
                            "operator": "in",
                            "value": huntToolName
                        }
                    ]
                };

                // Create a promise for each API call
                let promise = $resource(API.QUERY + 'solutionpacks').save({ $limit: ALL_RECORDS_SIZE }, queryBody).$promise
                    .then(function (response) {
                        if (Array.isArray(response['hydra:member']) && response['hydra:member'].length > 0) {
                            let huntToolDetails = _.map(response['hydra:member'], obj => _.pick(obj, ['name', 'label', 'version', 'uuid']));
                            return connectorService.getConnector(huntToolDetails[0].name, huntToolDetails[0].version)
                                .then(function (connector) {
                                    if (!connector) {
                                        toaster.error({
                                            body: 'The Connector "' + huntToolDetails[0].name + '" is not installed. Install the connector manually and re-run this wizard to complete the configuration'
                                        });
                                        return Promise.reject('Connector not installed');
                                    }
                                    // check default 
                                    var default_connector = connector.configuration.find(function (config) {
                                        return config.default;
                                    });
                                    //check if any of the cconnector config is not default
                                    // nist-nvd check is skipped
                                    $scope.connectorDefaultStatus[index] = true;
                                    if (angular.isUndefined(default_connector)) {
                                        let errorMessage = `The default configuration for the ${connector.label} connector not found.`
                                        toaster.error({
                                            body: errorMessage
                                        });
                                        $scope.connectorDefaultStatus[index] = false;
                                        return Promise.reject('Default configuration not found');
                                    }
                                    return marketplaceService.getContentDetails(API.BASE + 'solutionpacks/' + huntToolDetails[0].uuid + '?$relationships=true')
                                        .then(function (response) {
                                            if (connector.configuration.length > 0) {
                                                $scope.isConnectorsConfigured = true;
                                                return connectorService.getConnectorHealth(response.data, default_connector.config_id, default_connector.agent)
                                                    .then(function (data) {
                                                        // added data.name==="nist-nvd" to skip nist health check; 
                                                        // can remove it when not required 
                                                        if (data.name === "nist-nvd" || data.status === "Available") {
                                                            $scope.connectorHealthStatus[index] = true;
                                                        }
                                                    });
                                            } else {
                                                $scope.isConnectorsConfigured = false;
                                            }
                                        });
                                });
                        } else {
                            console.error('No data found in response[\'hydra:member\']');
                        }
                    })
                    .catch(function (error) {
                        console.error('An error occurred:', error);
                    });
                // Add the promise to the array
                promises.push(promise);
            }
            // Use Promise.all to wait for all promises to complete
            Promise.all(promises)
                .then(() => {
                    // After all promises are resolved, evaluate the condition
                    $scope.isConnectorsHealthy = false;
                    let indices = _.map(_.filter($scope.connectorHealthStatus, value => value === false), (value, index) => $scope.connectorHealthStatus.indexOf(value, index));
                    let defaultConfigNotPresent = _.filter($scope.connectorDefaultStatus, value => value === false);
                    const notConfigConnectors = _.uniq(indices).map(index => $scope.selectedEnv.huntTools[index]);
                    const toasterMessage = 'Connector ' + notConfigConnectors.join(', ') + ' is not configured';
                    if (defaultConfigNotPresent.length === 0) {
                        if (notConfigConnectors.length === 0) {
                            if (CommonUtils.isUndefined($scope.selectedEnv.autoInstallOutbreaks)) {
                                $scope.selectedEnv.autoInstallOutbreaks = {
                                    installSelectedOutbreaks: true,
                                    installOutbreaksFromLastXDays: 0,
                                    installOutbreakType: $scope.selectedEnv.installOutbreakType
                                }
                            } else {
                                $scope.selectedEnv.autoInstallOutbreaks.installOutbreakType = $scope.outbreakAlertSeverityList.slice();
                            }
                            WizardHandler.wizard('OutbreaksolutionpackWizard').next();
                        } else {
                            var huntToolIndex = $scope.selectedEnv.huntTools.indexOf(notConfigConnectors[0]);
                            $scope.params.activeTab = huntToolIndex;
                            loadActiveTab(huntToolIndex, notConfigConnectors[0]);
                            var connectorConfig = document.getElementById('accordion-connector-config-' + huntToolIndex);
                            connectorConfig.childNodes[2].classList.add('in');
                            toggleConnectorConfigSettings(huntToolIndex);
                            var paramsConfig = document.getElementById('accordion-params-config-' + huntToolIndex);
                            paramsConfig.childNodes[2].classList.replace('in', null);
                            toggleAdvancedSettings(huntToolIndex);
                            toaster.error({
                                body: toasterMessage
                            });
                        }
                    }
                })
                .catch(error => {
                    console.error('An error occurred in Promise.all:', error);
                });
        }

        function moveToFinish(installationForm) {
            if ($scope.selectedEnv.autoInstallOutbreaks.installSelectedOutbreaks) {
                if (installationForm.autoInstallationForm.installOutbreaksFromLastXDays.$invalid) {
                    installationForm.autoInstallationForm.installOutbreaksFromLastXDays.$touched = true;
                    installationForm.autoInstallationForm.installOutbreaksFromLastXDays.$untouched = false;
                    installationForm.autoInstallationForm.installOutbreaksFromLastXDays.$dirty = true;
                    toaster.error({
                        body: "Failed to validate the Outbreak Response Solution Pack auto installation criteria"
                    });
                    return;
                }
                if (installationForm.autoInstallationForm.OutbreakSeverities.$invalid) {
                    installationForm.autoInstallationForm.OutbreakSeverities.$touched = true;
                    installationForm.autoInstallationForm.OutbreakSeverities.$untouched = false;
                    installationForm.autoInstallationForm.OutbreakSeverities.$dirty = true;
                    toaster.error({
                        body: "Failed to validate the Outbreak Reponse Solution pack auto installation criteria"
                    });
                    return;
                }
            }
            initWebsocket();
            triggerPlaybook();
        }

        function threatHuntSchedule(scheduleForm) {
            if (scheduleForm.threatHuntWindowForm.$invalid) {
                scheduleForm.threatHuntWindowForm.timeFrameDays.$touched = true;
                scheduleForm.threatHuntWindowForm.timeFrameDays.$untouched = false;
                scheduleForm.threatHuntWindowForm.timeFrameDays.$dirty = true;
                return;
            }
            WizardHandler.wizard('OutbreaksolutionpackWizard').next();
        }

        function backStartPage() {
            WizardHandler.wizard('OutbreaksolutionpackWizard').previous();
        }

        function backThreatHuntSchedule() {
            $scope.isPlaybookExecuted = false;
            if (subscription) {
                websocketService.unsubscribe(subscription);
            }
            WizardHandler.wizard('OutbreaksolutionpackWizard').previous();
        }

        function backSelectHuntTools() {
            const index = $scope.selectedEnv.huntTools.indexOf(nistConnectorName);
            if (index !== -1) {
                $scope.selectedEnv.huntTools.splice(index, 1);
            }
            WizardHandler.wizard('OutbreaksolutionpackWizard').previous();
        }

        function getDisplayHuntTools() {
            $scope.displayHuntTools = (_.without($scope.selectedEnv.huntTools, 'NIST National Vulnerability Database')).join(', ');
        }

        function backThreatHuntConfig() {
            var selectedHuntTool = $scope.selectedEnv.huntTools[0];
            loadActiveTab(0, selectedHuntTool);
            WizardHandler.wizard('OutbreaksolutionpackWizard').previous();
        }

        function triggerPlaybook() {
            var queryPayload =
            {
                "request": $scope.selectedEnv
            }
            var queryUrl = API.MANUAL_TRIGGER + '906d2c36-8c7e-4fb6-ba06-6311fbefcf02';
            $http.post(queryUrl, queryPayload).then(function (response) {
                $scope.configPlaybookTaskID = response.data.task_id;
                console.log(response);
            });
        }

        function triggerAutoInstallOutbreaksPlaybook() {
            // var installOutbreakType = _.map($scope.selectedEnv.autoInstallOutbreaks.installOutbreakType, item => item + "_Severity_Outbreak_Alert");
            var queryPayload =
            {
                "request": { 'auto_install_outbreaks': $scope.selectedEnv.autoInstallOutbreaks, 'email_address': $scope.selectedEnv.emailAddress }
            }
            var queryUrl = API.MANUAL_TRIGGER + '7d924203-e5e3-4ce5-b704-e8f3283c7b92';
            $http.post(queryUrl, queryPayload).then(function (response) {
                toaster.success({
                    body: 'Auto install Outbreak Alerts playbook triggered successfully.'
                });
            });
        }

        //provide i18n support
        function _handleTranslations() {
            let widgetData = {
                name: $scope.config.name,
                version: $scope.config.version
            };
            let widgetNameVersion = widgetUtilityService.getWidgetNameVersion(widgetData);
            if (widgetNameVersion) {
                widgetUtilityService.checkTranslationMode(widgetNameVersion).then(function () {
                    $scope.viewWidgetVars = {
                        // Create your translating static string variables here
                        START_PAGE_WZ_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.START_PAGE_WZ_TITLE'),
                        LABEL_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.LABEL_TITLE'),
                        START_PAGE_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.START_PAGE_TITLE'),
                        START_PAGE_DISCRIPTION: widgetUtilityService.translate('outbreakAlertConfiguration.START_PAGE_DISCRIPTION'),
                        PREREQUISITIES_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_TITLE'),
                        PREREQUISITIES_1: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_1'),
                        PREREQUISITIES_2: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_2'),
                        PREREQUISITIES_3: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_3'),
                        PREREQUISITIES_4: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_4'),
                        PREREQUISITIES_5: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_5'),
                        PREREQUISITIES_6: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_6'),
                        PREREQUISITIES_7: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_7'),
                        PREREQUISITIES_8: widgetUtilityService.translate('outbreakAlertConfiguration.PREREQUISITIES_8'),
                        START_PAGE_Button: widgetUtilityService.translate('outbreakAlertConfiguration.START_PAGE_Button'),

                        SECOND_PAGE_WZ_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.SECOND_PAGE_WZ_TITLE'),
                        SECOND_PAGE_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.SECOND_PAGE_TITLE'),
                        SECOND_PAGE_DISCRIPTION: widgetUtilityService.translate('outbreakAlertConfiguration.SECOND_PAGE_DISCRIPTION'),
                        SECOND_PAGE_BACK: widgetUtilityService.translate('outbreakAlertConfiguration.SECOND_PAGE_BACK'),
                        SECOND_PAGE_NEXT: widgetUtilityService.translate('outbreakAlertConfiguration.SECOND_PAGE_NEXT'),

                        THIRD_PAGE_WZ_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_WZ_TITLE'),
                        THIRD_PAGE_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_TITLE'),
                        THIRD_PAGE_TOGGLE_CONFIG: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_TOGGLE_CONFIG'),
                        THIRD_PAGE_TOGGLE_PARAMS: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_TOGGLE_PARAMS'),
                        THIRD_PAGE_FAZ_PARAMS: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_FAZ_PARAMS'),
                        THIRD_PAGE_FSM_PARAMS: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_FSM_PARAMS'),
                        THIRD_PAGE_QRADAR_PARAMS: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_QRADAR_PARAMS'),
                        THIRD_PAGE_SPLUNK_PARAMS: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_SPLUNK_PARAMS'),
                        THIRD_PAGE_BACK: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_BACK'),
                        THIRD_PAGE_NEXT: widgetUtilityService.translate('outbreakAlertConfiguration.THIRD_PAGE_NEXT'),

                        FOURTH_PAGE_WZ_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_WZ_TITLE'),
                        FOURTH_PAGE_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_TITLE'),
                        FOURTH_PAGE_SECTION_1_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_1_TITLE'),
                        FOURTH_PAGE_SECTION_1_DISCRIPTION: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_1_DISCRIPTION'),
                        FOURTH_PAGE_SECTION_1_PARAM_1: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_1_PARAM_1'),
                        FOURTH_PAGE_SECTION_1_PARAM_2: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_1_PARAM_2'),
                        FOURTH_PAGE_SECTION_1_TOOLTIP_1: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_1_TOOLTIP_1'),
                        FOURTH_PAGE_SECTION_1_TOOLTIP_2: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_1_TOOLTIP_2'),
                        FOURTH_PAGE_SECTION_2_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_2_TITLE'),
                        FOURTH_PAGE_SECTION_2_DISCRIPTION: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_SECTION_2_DISCRIPTION'),
                        FOURTH_PAGE_BACK: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_BACK'),
                        FOURTH_PAGE_NEXT: widgetUtilityService.translate('outbreakAlertConfiguration.FOURTH_PAGE_NEXT'),

                        FIFTH_PAGE_WZ_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_WZ_TITLE'),
                        FIFTH_PAGE_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_TITLE'),
                        FIFTH_PAGE_SECTION_1_HEADING: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_HEADING'),
                        FIFTH_PAGE_SECTION_1_DISCRIPTION_1: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_DISCRIPTION_1'),
                        FIFTH_PAGE_SECTION_1_LABLE_INSTALL_ALL: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_LABLE_INSTALL_ALL'),
                        FIFTH_PAGE_SECTION_1_LABLE_INSTALL_SELECTED: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_LABLE_INSTALL_SELECTED'),
                        FIFTH_PAGE_SECTION_1_LAST_N_DAYS: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_LAST_N_DAYS'),
                        FIFTH_PAGE_SECTION_1_SEVERITY: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_SEVERITY'),
                        FIFTH_PAGE_SECTION_1_SEVERITY_TOOLTIP: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_SEVERITY_TOOLTIP'),
                        FIFTH_PAGE_SECTION_1_SEVERITY_ERROR_MSG: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_1_SEVERITY_ERROR_MSG'),
                        FIFTH_PAGE_SECTION_2_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_2_TITLE'),
                        FIFTH_PAGE_SECTION_2_EMAIL: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_2_EMAIL'),
                        FIFTH_PAGE_SECTION_2_EMAIL_TOOLTIP: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_2_EMAIL_TOOLTIP'),
                        FIFTH_PAGE_SECTION_2_EMAIL_VALIDATION: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_SECTION_2_EMAIL_VALIDATION'),
                        FIFTH_PAGE_BACK: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_BACK'),
                        FIFTH_PAGE_NEXT: widgetUtilityService.translate('outbreakAlertConfiguration.FIFTH_PAGE_NEXT'),

                        SIXTH_PAGE_WZ_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_WZ_TITLE'),
                        SIXTH_PAGE_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_TITLE'),
                        SIXTH_PAGE_DISCRIPTION_1: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_DISCRIPTION_1'),
                        SIXTH_PAGE_DISCRIPTION_2_1: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_DISCRIPTION_2_1'),
                        SIXTH_PAGE_DISCRIPTION_2_2: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_DISCRIPTION_2_2'),
                        SIXTH_PAGE_DISCRIPTION_2_3: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_DISCRIPTION_2_3'),
                        SIXTH_PAGE_SUMMARY: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY'),
                        SIXTH_PAGE_SUMMARY_HEADING_1: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_1'),
                        SIXTH_PAGE_SUMMARY_HEADING_2: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_2'),
                        SIXTH_PAGE_SUMMARY_HEADING_3: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_3'),
                        SIXTH_PAGE_SUMMARY_HEADING_4: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_4'),
                        SIXTH_PAGE_SUMMARY_HEADING_5: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_5'),
                        SIXTH_PAGE_SUMMARY_HEADING_5_1: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_5_1'),
                        SIXTH_PAGE_SUMMARY_HEADING_5_2: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_5_2'),
                        SIXTH_PAGE_SUMMARY_HEADING_6: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_SUMMARY_HEADING_6'),
                        SIXTH_PAGE_AUTO_INSTALL_HEADING_1: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_AUTO_INSTALL_HEADING_1'),
                        SIXTH_PAGE_AUTO_INSTALL_BUTTON_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_AUTO_INSTALL_BUTTON_LABEL'),
                        SIXTH_PAGE_BACK: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_BACK'),
                        SIXTH_PAGE_NEXT: widgetUtilityService.translate('outbreakAlertConfiguration.SIXTH_PAGE_NEXT'),

                        DIRECTIVE_MESSAGE_1: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_MESSAGE_1'),
                        DIRECTIVE_NO_OPTION: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_NO_OPTION'),
                        DIRECTIVE_YES_OPTION: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_YES_OPTION'),
                        DIRECTIVE_SCHEDULE_MESSAGE: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_SCHEDULE_MESSAGE'),
                        DIRECTIVE_TIME_BY: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_TIME_BY'),
                        DIRECTIVE_CRON_VALUE: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_CRON_VALUE'),
                        DIRECTIVE_CRON_VALUE_HR: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_CRON_VALUE_HR'),
                        DIRECTIVE_CRON_VALUE_DAILY: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_CRON_VALUE_DAILY'),
                        DIRECTIVE_CRON_VALUE_WEEKLY: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_CRON_VALUE_WEEKLY'),
                        DIRECTIVE_CRON_VALUE_MONTHLY: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_CRON_VALUE_MONTHLY'),
                        DIRECTIVE_CRON_VALUE_YEARLY: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_CRON_VALUE_YEARLY'),
                        DIRECTIVE_MINUTE_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_MINUTE_LABEL'),
                        DIRECTIVE_HOUR_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_HOUR_LABEL'),
                        DIRECTIVE_MONTH_DAY_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_MONTH_DAY_LABEL'),
                        DIRECTIVE_MONTH_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_MONTH_LABEL'),
                        DIRECTIVE_WEEK_DAY_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_WEEK_DAY_LABEL'),
                        DIRECTIVE_TIMEZONE_LABEL: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_TIMEZONE_LABEL'),
                        DIRECTIVE_TIMEZONE_TOOLTIP: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_TIMEZONE_TOOLTIP'),
                        DIRECTIVE_SAVE_BUTTON: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_SAVE_BUTTON'),
                        DIRECTIVE_SAVEING_BUTTON: widgetUtilityService.translate('outbreakAlertConfiguration.DIRECTIVE_SAVEING_BUTTON'),

                        THREAT_HUNT_INTEGRATION_CONFIG_CHANGE: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_CHANGE'),
                        THREAT_HUNT_INTEGRATION_CONFIG_TITLE1: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_TITLE1'),
                        THREAT_HUNT_INTEGRATION_CONFIG_MSG1: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_MSG1'),
                        THREAT_HUNT_INTEGRATION_CONFIG_MSG2: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_MSG2'),
                        THREAT_HUNT_INTEGRATION_CONFIG_MSG3: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_MSG3'),
                        THREAT_HUNT_INTEGRATION_CONFIG_MSG4: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_MSG4'),
                        THREAT_HUNT_INTEGRATION_HEALTH_TITLE: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_HEALTH_TITLE'),
                        THREAT_HUNT_INTEGRATION_CONFIG_NAME: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_CONFIG_NAME'),
                        THREAT_HUNT_INTEGRATION_DEFAULT: widgetUtilityService.translate('outbreakAlertConfiguration.THREAT_HUNT_INTEGRATION_DEFAULT'),
                    };
                });
            }
            else {
                $timeout(function () {
                    cancel();
                }, 100)
            }
        }

        function cancel() {
            $uibModalInstance.dismiss('cancel');
        }

        function init() {
            var pagedCollection = new PagedCollection('keys');
            var query = {
                logic: 'AND',
                limit: 1,
                filters: [{
                    field: 'key',
                    operator: 'eq',
                    value: 'outbreak-alert-config'
                }
                ],
                __selectFields: ["jSONValue"]
            };

            pagedCollection.query = new Query(query);
            pagedCollection.load().then(function () {
                console.log(pagedCollection);
                if (pagedCollection.data['hydra:member'].length > 0 > 0) {
                    if (JSON.parse(pagedCollection.data['hydra:member'][0].jSONValue) !== null) {
                        $scope.selectedEnv = JSON.parse(pagedCollection.data['hydra:member'][0].jSONValue).saveConfig;
                    }
                    let index = $scope.selectedEnv.huntTools.indexOf(nistConnectorName);
                    if (index !== -1) {
                        $scope.selectedEnv.huntTools.splice(index, 1);
                    }
                }
            });
            if (!currentPermissionsService.availablePermission('workflows', 'execute')) {
                toaster.error({
                    body: "You dont have permission to execute the playbook"
                });
                return;
            }
            _handleTranslations();
        }
        init();
    }
})();