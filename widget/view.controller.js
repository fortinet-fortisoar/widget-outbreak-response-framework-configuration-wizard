/* Copyright start
  MIT License
  Copyright (c) 2025 Fortinet Inc
  Copyright end */
'use strict';
(function () {
    angular
        .module('cybersponse')
        .controller('outbreakAlertConfiguration220Ctrl', outbreakAlertConfiguration220Ctrl);

    outbreakAlertConfiguration220Ctrl.$inject = ['$scope', '$http', '$q', 'WizardHandler', '$controller', '$state', 'connectorService', 'CommonUtils', '$window', 'toaster', 'currentPermissionsService', '_', '$resource', 'API', 'ALL_RECORDS_SIZE', 'widgetBasePath', '$rootScope', 'websocketService', '$timeout', 'widgetUtilityService', 'PagedCollection', 'Query', 'Modules', 'config'];

    function outbreakAlertConfiguration220Ctrl($scope, $http, $q, WizardHandler, $controller, $state, connectorService, CommonUtils, $window, toaster, currentPermissionsService, _, $resource, API, ALL_RECORDS_SIZE, widgetBasePath, $rootScope, websocketService, $timeout, widgetUtilityService, PagedCollection, Query, Modules, config) {
        $controller('BaseConnectorCtrl', {
            $scope: $scope
        });
        $scope.processingPicklist = false;
        $scope.huntparams = {};
        $scope.isConnectorsHealthy = false;
        $scope.isConnectorsInstalled = false;
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
        $scope.getDisplayHuntTools = getDisplayHuntTools;
        $scope.loadActiveTab = loadActiveTab;
        $scope.connectorInstalledOnAgents = [];
        $scope.configPlaybookTaskID = '';
        $scope.installedConnectors = [];
        $scope.connectorReady = [];
        $scope.isPlaybookExecuted = false;
        $scope.toggleConnectorConfigSettings = { open: true };
        $scope.toggleParametersSettings = { open: false };
        $scope.backNotification = backNotification;
        $scope.nextNotification = nextNotification;
        $scope.setConnectorType = setConnectorType;
        $scope.setConnectorConfiguration = setConnectorConfiguration;
        $scope.checkFAZConnectorHealth = checkFAZConnectorHealth;
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
        $scope.config = config;
        $scope.connectorTypeList = ['Self', 'Agent'];
        $scope.allConfigurations = [];
        const nistConnectorName = 'NIST National Vulnerability Database';
        const skipHealthCheckForConnectors = [nistConnectorName , 'Fortinet FortiAnalyzer'];

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
        var fazConnector;

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

        function loadActiveTab(tabIndex) {
            $scope.toggleConnectorConfigSettings = { open: true };
            $scope.toggleParametersSettings = { open: false };
            if (CommonUtils.isUndefined(tabIndex)) {
                if (CommonUtils.isUndefined($scope.params.activeTab)) {
                    $scope.params = {
                        activeTab: 0
                    }
                }
            }
            else {
                $scope.params = {
                    activeTab: tabIndex
                };
                $scope.selectedConnectorName = $scope.installedConnectors[tabIndex].label;
            }
        }

        //update connector Configuration list as per connector type
        function setConnectorType() {
            $scope.allConfigurations = [];
            const _connectorName = fazConnector.name;
            const _connectorVersion = fazConnector.version;
            if ($scope.config.connectorType === 'Self') {
                connectorService.getConnector(_connectorName, _connectorVersion).then(function (connectorDetails) {
                    $scope.allConfigurations.push(...connectorDetails.configuration);
                });
            }
            else {
                let connectorInfo = {
                    name: _connectorName,
                    version: _connectorVersion
                }
                connectorService.getAgents(connectorInfo).then(function (agentDetails) { //check and fetch agent
                    if (agentDetails && agentDetails.length > 0) {
                        agentDetails.forEach(agentElement => {
                            connectorService.getConnector(_connectorName, _connectorVersion, agentElement.agent).then(function (connectorDetails) { //check and fetch agent
                                $scope.allConfigurations.push(...connectorDetails.configuration);
                            });
                        });
                    }
                });
            }
        }

        function setConnectorConfiguration(){
            if($scope.config.selectedConfig){
                $scope.selectedEnv.fazConnectorConfig = $scope.config.selectedConfig;
                checkFAZConnectorHealth();
            }
        }

        function checkFAZConnectorHealth() {
            $scope.healthCheckProcessing = true;
            let connectorMetaData = {
                'name': fazConnector.name,
                'version': fazConnector.version
            }
            if ($scope.config.connectorType === 'Agent'){
                $scope.config.fazConnectorHealth = {'status' : $scope.config.selectedConfig.health_status.status};
                $scope.healthCheckProcessing = false;
            } else {
                connectorService.getConnectorHealth(connectorMetaData, $scope.config.selectedConfig.config_id).then(function (connectorHealth) {
                    $scope.config.fazConnectorHealth = connectorHealth;
                }, function (error) {
                    console.log(error);
                    return;
                }).finally(function () {
                    $scope.healthCheckProcessing = false;
                })
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

        async function configHuntTool() {
            $scope.isConnectorsInstalled = true;
            $scope.selectedConnectorName = nistConnectorName;
            $scope.toggleSelectConfiguration = { open: false };
            const queryBody = {
                logic: "AND",
                filters: [{
                    type: "primitive",
                    field: "key",
                    value: "outbreak-threat-hunt-tools-params",
                    operator: "eq",
                    _operator: "eq"
                }]
            };
            const queryString = { $limit: ALL_RECORDS_SIZE };
            try {
                const response = await $resource(API.QUERY + 'keys').save(queryString, queryBody).$promise;

                if (response['hydra:member'] && response['hydra:member'].length > 0) {
                    var selectedConnectors = angular.copy($scope.selectedEnv.huntTools);
                    if (selectedConnectors[0] !== nistConnectorName) {
                        selectedConnectors.splice(0, 0, nistConnectorName);
                    }
                    $scope.installedConnectors = [];
                    $scope.threatHuntToolsParams = response['hydra:member'][0].jSONValue;
                    for (let index = 0; index < selectedConnectors.length; index++) {
                        await _fetchConnectorDetails(selectedConnectors[index], index);
                    }
                    if (_.every($scope.connectorReady, val => val === true)) {
                        loadActiveTab($state.params.tabIndex);
                        if ($scope.selectedEnv.huntTools[0] !== nistConnectorName) {
                            $scope.selectedEnv.huntTools.splice(0, 0, nistConnectorName);
                        }
                        $scope.isConnectorsInstalled = false;
                        WizardHandler.wizard('OutbreaksolutionpackWizard').next();
                    }
                    fazConnector = _.find($scope.installedConnectors,{label  : 'Fortinet FortiAnalyzer'});
                    if(fazConnector){
                        setConnectorType();
                    }
                } else {
                    toaster.error({ body: 'Threat Hunt Tool parameters is not found in Key-Store' });
                }
            } catch (error) {
                console.error('Error in configHuntTool:', error);
                toaster.error({ body: 'An error occurred while loading threat hunt tools.' });
            }
        }

        function _fetchConnectorDetails(connectorName, index) {
            return new Promise((resolve) => {
                const queryBody = {
                    "sort": [
                        {
                            "field": "label",
                            "direction": "ASC"
                        }
                    ],
                    "page": 1,
                    "limit": 30,
                    "logic": "AND",
                    "filters": [
                        {
                            "field": "type",
                            "operator": "in",
                            "value": [
                                "connector"
                            ]
                        },
                        {
                            "field": "installed",
                            "operator": "eq",
                            "value": true
                        },
                        {
                            "logic": "OR",
                            "filters": [
                                {
                                    "field": "development",
                                    "operator": "eq",
                                    "value": false
                                },
                                {
                                    "field": "type",
                                    "operator": "eq",
                                    "value": "widget"
                                },
                                {
                                    "field": "type",
                                    "operator": "eq",
                                    "value": "solutionpack"
                                }
                            ]
                        }
                    ],
                    "search": "NIST National Vulnerability Database"
                };
                const url = `solutionpacks?$limit=${ALL_RECORDS_SIZE}&$page=1&$search=${connectorName.replace(/ /g, '%20')}`;
                $http.post(API.QUERY + url, queryBody).then(async (response) => {
                    if (response.data['hydra:member'].length > 0) {
                        try {
                            const connectorMeta = angular.copy(response.data['hydra:member'][0]);
                            const connector = await connectorService.getConnector(connectorMeta.name, connectorMeta.version);
                            connectorMeta.connectorInfo = angular.copy(connector);
                            connectorMeta.connectorInfo.baseId = connector.id;
                            await _loadConnectorAgents(connectorMeta, index);
                            $scope.installedConnectors[index] = connectorMeta;
                            $scope.installedConnectors[index].healthStatus = false;
                            $scope.installedConnectors[index].defaultConfig = false;
                            $scope.connectorReady[index] = true;
                            resolve();
                        } catch (err) {
                            console.error('Error in getConnector:', err);
                            $scope.connectorReady[index] = false;
                            resolve();
                        }
                    } else {
                        console.warn(`${connectorName} connector is not installed`);
                        $scope.connectorReady[index] = false;
                        resolve();
                    }
                }).catch((error) => {
                    console.error('An error occurred:', error);
                    $scope.connectorReady[index] = false;
                    resolve();
                });
            });
        }

        function _loadConnectorAgents(installedConnector, index) {
            return connectorService.getAgents(installedConnector).then((installedAgents) => {
                $scope.connectorInstalledOnAgents[index] = installedAgents;
                return installedAgents;
            }).catch((err) => {
                console.error('Error in getAgents:', err);
                return [];
            });
        }

        $scope.$on('healthCheckDetails', function (event, connectorDetails) {
            var connector = angular.copy(connectorDetails);
            const connectorConfig = _.find(connector.connectorInfo.configuration, { config_id: connector.config_id });
            $scope.installedConnectors[connector.tabIndex].defaultConfig = connector.connectorInfo.configuration.some(item => item.default === true);
            if (!CommonUtils.isUndefined(connectorConfig) && connectorConfig.status === "Available") {
                $scope.installedConnectors[connector.tabIndex].healthStatus = true;
                _.assign(connector.connectorInfo, { "configuration": connectorConfig });
                _.assign(connector.connectorInfo, { "playbook_collections": connector.connectorInfo.playbook_collections[0] });
                _.assign(connector.connectorInfo, { "uuid": $scope.installedConnectors[connector.tabIndex].uuid });
            } else {
                $scope.toggleConnectorConfigSettings = { open: true };
                $scope.toggleParametersSettings = { open: false };
                $scope.installedConnectors[connector.tabIndex].healthStatus = false;
                $scope.installedConnectors[connector.tabIndex].defaultConfig = false;
            }
        });

        $scope.$on('toggleAgentMode', function (event, data) {
            $scope.installedConnectors[data.tabIndex].healthStatus = false;
            $scope.installedConnectors[data.tabIndex].defaultConfig = false;
        });

        $scope.$on('configurationChanged', function (event, data) {
            $scope.installedConnectors[data.tabIndex].healthStatus = false;
            $scope.installedConnectors[data.tabIndex].defaultConfig = false;
        });

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

        function backNotification() {
            WizardHandler.wizard('OutbreaksolutionpackWizard').previous();
        }

        function nextNotification(threatHuntConfigForm) {
            if(!$scope.config.selectedConfig && threatHuntConfigForm.selectConfigForm && (threatHuntConfigForm.selectConfigForm.$invalid || threatHuntConfigForm.selectConfigForm.$pristine)){
                toaster.error({
                     body: 'Select atleast one configuration for Fortinet FortiAnalyzer'
                 });
                 _defaultConfigurationError();
                 return;
            }
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

        function _defaultConfigurationError(){
            var huntToolIndex = $scope.selectedEnv.huntTools.indexOf('Fortinet FortiAnalyzer');
            _activeErrorTab('Fortinet FortiAnalyzer', huntToolIndex);
            $scope.toggleConnectorConfigSettings = { open: false };
            $scope.toggleParametersSettings = { open: false };
            $scope.toggleSelectConfiguration = { open : true };
            
            $scope.params = {
                activeTab: huntToolIndex
            };
            $scope.selectedConnectorName = $scope.installedConnectors[huntToolIndex].label;
        }

        function _connectorErrorHandling(threatHuntTool) {
            var huntToolIndex = $scope.selectedEnv.huntTools.indexOf(threatHuntTool);
            _activeErrorTab(threatHuntTool, huntToolIndex);
            loadActiveTab(huntToolIndex);
            var paramsConfig = document.getElementById('accordion-params-config-' + huntToolIndex);
            paramsConfig.childNodes[2].classList.add('in');
            $scope.toggleParametersSettings = { open: true };
            var connectorConfig = document.getElementById('accordion-connector-config-' + huntToolIndex);
            connectorConfig.childNodes[2].classList.replace('in', null);
            $scope.toggleConnectorConfigSettings = { open: false };
            toaster.error({
                body: threatHuntTool + ' Threat Hunt Tool parameters are required'
            });
        }

        function _checkConnectorHealth() {
            $scope.isConnectorsHealthy = true;
            const invalidConnectorLabels = _.chain($scope.installedConnectors)
                .filter(c => !(c.healthStatus && c.defaultConfig) && !skipHealthCheckForConnectors.includes(c.label))
                .map('label')
                .value();
            if (_.isEmpty(invalidConnectorLabels)) {
                // All connectors are valid
                $scope.isConnectorsHealthy = false;
                var nistConnectorIndex = _.findIndex($scope.installedConnectors, { label: nistConnectorName });
                if (!$scope.installedConnectors[nistConnectorIndex].connectorInfo.configuration[0].default && $scope.installedConnectors[nistConnectorIndex].label === nistConnectorName) {
                    $scope.params.activeTab = nistConnectorIndex;
                    loadActiveTab(nistConnectorIndex);
                    toaster.error({
                        body: `The default configuration for the ${$scope.installedConnectors[nistConnectorIndex].label} connector not found.`
                    });
                    return;
                }
                if (CommonUtils.isUndefined($scope.selectedEnv.autoInstallOutbreaks)) {
                    $scope.selectedEnv.autoInstallOutbreaks = {
                        installSelectedOutbreaks: true,
                        installOutbreaksFromLastXDays: 0,
                        installOutbreakType: $scope.selectedEnv.installOutbreakType
                    };
                } else {
                    $scope.selectedEnv.autoInstallOutbreaks.installOutbreakType = $scope.outbreakAlertSeverityList.slice();
                }
                if($scope.config.fazConnectorHealth && $scope.config.fazConnectorHealth.status !== 'Available'){
                    toaster.error({
                        body: `Check health failed for Fortinet FortiAnalyzer: ${$scope.config.selectedConfig.name}`
                    });
                    _defaultConfigurationError();
                    return;
                }
                WizardHandler.wizard('OutbreaksolutionpackWizard').next();
            } else {
                var huntToolIndex = $scope.selectedEnv.huntTools.indexOf(invalidConnectorLabels[0]);
                $scope.params.activeTab = huntToolIndex;
                loadActiveTab(huntToolIndex);
                $scope.isConnectorsHealthy = false;
                if (!$scope.installedConnectors[huntToolIndex].healthStatus) {
                    toaster.error({
                        body: 'The ' + $scope.installedConnectors[huntToolIndex].label + ' either not configured or please wait until the configuration health is being checked.'
                    });
                    return;
                }
                if (!$scope.installedConnectors[huntToolIndex].defaultConfig) {
                    toaster.error({
                        body: `The default configuration for the ${$scope.installedConnectors[huntToolIndex].label} connector not found.`
                    });
                    return;
                }
            }
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
            $scope.toggleConnectorConfigSettings = { open: true };
            $scope.toggleParametersSettings = { open: false };
            loadActiveTab(0);
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
                if (pagedCollection.data['hydra:member'].length > 0) {
                    if (JSON.parse(pagedCollection.data['hydra:member'][0].jSONValue) !== null) {
                        $scope.selectedEnv = JSON.parse(pagedCollection.data['hydra:member'][0].jSONValue).saveConfig;
                    }
                    let index = $scope.selectedEnv.huntTools.indexOf(nistConnectorName);
                    if (index !== -1) {
                        $scope.selectedEnv.huntTools.splice(index, 1);
                    }
                }
            });
            Modules.get({
                module: 'teams',
                $limit: ALL_RECORDS_SIZE,
            }).$promise.then(function (result) {
                $scope.owners = result['hydra:member'];
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