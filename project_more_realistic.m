% IEEE 14-bus (MATPOWER) — DoS / DoD / FDI with Q-limit enforcement & PV->PQ switching,
% plus NO-ATTACK baseline.
%
% - AC power flow with MATPOWER
% - DoS: hold last-good load vector Pd during window
% - DoD: double loads at target buses during window
% - FDI: corrupt measured Vm (telemetry only) during window
%
% IMPORTANT:
%   - Slack bus is kept in the power flow
%   - All analysis (RMS deviations, violations, heatmaps, tables, etc.)
%     is computed on NON-SLACK buses only (as in most cyber-attack papers).
clear; close all; clc;

%% --- MATPOWER PATH (EDIT IF NEEDED) ---
% addpath(genpath('C:\Users\YOURNAME\Documents\MATLAB\matpower'));  % <-- set your path

%% --- CONFIG ---
rng(0);                                   % reproducible
config.nSteps      = 144;                 % timesteps (e.g., 10-min steps over a day)
config.Vlow        = 0.95;                % voltage lower limit (pu)
config.Vhigh       = 1.05;                % voltage upper limit (pu)

% Attack windows (in timesteps)
config.DoS_times   = 20:50;               % DoS: hold last-good Pd
config.DoD_times   = 100:130;             % DoD: double target-bus loads
config.FDI_times   = 60:90;               % FDI: corrupt measured Vm (telemetry only)

% DoD parameters
config.target_buses = [5 7 9];            % candidate targets for DoD
config.DoD_amp      = 1.5;                % multiply Pd by 1.5 (load increase)

% FDI parameters (applied to measured Vm only, post-solve)
config.FDI_offset   = 0.1;               % +0.1 pu

% Diurnal load profile
config.noise_profile = @(h) (1 + 0.15*sin(2*pi*h/24));  % 15% day-night swing

% Anomaly threshold (RMS from 1 pu, true state) on NON-SLACK buses
config.anom_thresh  = 0.10;               % 10%

%% --- LOAD CASE ---
mpc0 = loadcase('case14');
nBus = size(mpc0.bus,1);
nGen = size(mpc0.gen,1);
Pd0  = mpc0.bus(:,3);

% Identify slack bus and non-slack buses (for analysis)
slack_idx = find(mpc0.bus(:,2) == 3);   % ref bus
if numel(slack_idx) ~= 1
    error('Expected exactly one slack bus.');
end
all_buses = 1:nBus;
nonSlack  = setdiff(all_buses, slack_idx);   % analysis only on these buses

% Tighten Q limits to accentuate PV->PQ switching (optional)
q_span = 35;                 % +/- MVAr
mpc0.gen(:,4) =  q_span;     % Qmax
mpc0.gen(:,5) = -q_span;     % Qmin

% Baseline PV bus indices (1=PQ, 2=PV, 3=REF)
pv0_idx = find(mpc0.bus(:,2) == 2);

%% --- STORAGE (ATTACKED CASE) ---
Vm_true   = nan(nBus,config.nSteps);    % solved voltages (true physics)
Va_true   = nan(nBus,config.nSteps);
Vm_meas   = nan(nBus,config.nSteps);    % measured voltages (after FDI)
genP      = nan(nGen,config.nSteps);
genQ      = nan(nGen,config.nSteps);
totalGenP = nan(1,config.nSteps);
totalLoadP= nan(1,config.nSteps);
totalLoss = nan(1,config.nSteps);

attack_mask      = zeros(1,config.nSteps,'uint8');  % bitmask: 1=DoS, 2=DoD, 4=FDI
DoD_bus_applied  = nan(1,config.nSteps);            % not used, but kept for completeness

satQmax   = false(nGen, config.nSteps); % Qg == Qmax
satQmin   = false(nGen, config.nSteps); % Qg == Qmin
pv_to_pq  = false(numel(pv0_idx), config.nSteps); % PV->PQ events at baseline-PV buses

anomaly   = false(1,config.nSteps);
viol_low  = false(nBus, config.nSteps);  % will be nonzero only on nonSlack
viol_high = false(nBus, config.nSteps);

%% --- MATPOWER OPTIONS: enforce Q limits & PV->PQ switching ---
try
    mpopt = mpoption('verbose',0,'out.all',0,'pf.enforce_q_lims',1);
catch
    mpopt = mpoption('verbose',0,'out.all',0,'enforce_q_lims',1);
end

%% --- ATTACKED SIMULATION ---
mpc   = mpc0;
lastPd = Pd0;   % for DoS

for t = 1:config.nSteps
    hour    = mod(t-1, 24);
    profile = config.noise_profile(hour);
    truePd  = Pd0 * profile;

    % DoS: hold last good Pd; else update to truePd
    if ismember(t, config.DoS_times)
        attack_mask(t) = bitor(attack_mask(t), uint8(1));
        mpc.bus(:,3) = lastPd;
    else
        mpc.bus(:,3) = truePd;
        lastPd       = truePd;
    end

    % DoD: physical load increase (double loads) on target buses
    if ismember(t, config.DoD_times)
        attack_mask(t) = bitor(attack_mask(t), uint8(2));
        for b = config.target_buses
            mpc.bus(b,3) = mpc.bus(b,3) * config.DoD_amp;   % 2x load
        end
        DoD_bus_applied(t) = NaN; % placeholder; not used
    end

    % Solve TRUE physics with Q-limit enforcement
    try
        results = runpf(mpc, mpopt);
        Vm_true(:,t) = results.bus(:,8);
        Va_true(:,t) = results.bus(:,9);
        genP(:,t)    = results.gen(:,2);
        genQ(:,t)    = results.gen(:,3);
        totalGenP(t)  = sum(results.gen(:,2),'omitnan');
        totalLoadP(t) = sum(results.bus(:,3),'omitnan');
        totalLoss(t)  = totalGenP(t) - totalLoadP(t);

        % Q-limit saturation logs
        epsQ = 1e-5;
        Qmax = mpc.gen(:,4); Qmin = mpc.gen(:,5);
        satQmax(:,t) = isfinite(Qmax) & (results.gen(:,3) >= Qmax - epsQ);
        satQmin(:,t) = isfinite(Qmin) & (results.gen(:,3) <= Qmin + epsQ);

        % PV->PQ switching logs (relative to baseline PV set)
        bus_type = results.bus(:,2); % 1=PQ, 2=PV, 3=REF
        pv_to_pq(:,t) = bus_type(pv0_idx) == 1;

    catch ME
        warning('runpf failed (attacked) at t=%d: %s', t, ME.message);
        Vm_true(:,t)=NaN; Va_true(:,t)=NaN;
        genP(:,t)=NaN; genQ(:,t)=NaN;
        totalGenP(t)=NaN; totalLoadP(t)=NaN; totalLoss(t)=NaN;
        satQmax(:,t)=false; satQmin(:,t)=false; pv_to_pq(:,t)=false;
    end

    % Measured voltages (FDI): applied AFTER solving true state
    Vm_meas(:,t) = Vm_true(:,t);
    if ismember(t, config.FDI_times)
        attack_mask(t) = bitor(attack_mask(t), uint8(4));
        Vm_meas(:,t)   = Vm_meas(:,t) + config.FDI_offset;
    end

    % Violations & anomaly on TRUE state
    if all(isfinite(Vm_true(nonSlack,t)))
        viol_low(:,t)  = false;  % reset slack + nonSlack
        viol_high(:,t) = false;
        viol_low(nonSlack,t)  = Vm_true(nonSlack,t) < config.Vlow;
        viol_high(nonSlack,t) = Vm_true(nonSlack,t) > config.Vhigh;
        anomaly(t) = rms(Vm_true(nonSlack,t) - 1) > config.anom_thresh;
    else
        viol_low(:,t)=false; viol_high(:,t)=false; anomaly(t)=true;
    end
end

%% --- BASELINE (NO ATTACK) WITH SAME DIURNAL PROFILE ---
Vm_base   = nan(nBus, config.nSteps);
Va_base   = nan(nBus, config.nSteps);
genP_base = nan(nGen, config.nSteps);
genQ_base = nan(nGen, config.nSteps);
Gen_base  = nan(1,   config.nSteps);
Load_base = nan(1,   config.nSteps);
Loss_base = nan(1,   config.nSteps);
satQmax_base   = false(nGen, config.nSteps);
satQmin_base   = false(nGen, config.nSteps);
pv_to_pq_base  = false(numel(pv0_idx), config.nSteps);

mpcB = mpc0;  % independent baseline model

for tt = 1:config.nSteps
    hourB    = mod(tt-1, 24);
    profileB = config.noise_profile(hourB);
    mpcB.bus(:,3) = Pd0 * profileB;   % update to true load, NO attacks

    try
        rB = runpf(mpcB, mpopt);
        Vm_base(:,tt) = rB.bus(:,8);
        Va_base(:,tt) = rB.bus(:,9);
        genP_base(:,tt) = rB.gen(:,2);
        genQ_base(:,tt) = rB.gen(:,3);

        Gen_base(tt)  = sum(rB.gen(:,2),'omitnan');
        Load_base(tt) = sum(rB.bus(:,3),'omitnan');
        Loss_base(tt) = Gen_base(tt) - Load_base(tt);

        % Q-limit / switching logs (baseline)
        epsQ = 1e-5;
        QmaxB = mpcB.gen(:,4); QminB = mpcB.gen(:,5);
        satQmax_base(:,tt) = isfinite(QmaxB) & (rB.gen(:,3) >= QmaxB - epsQ);
        satQmin_base(:,tt) = isfinite(QminB) & (rB.gen(:,3) <= QminB + epsQ);

        bus_typeB = rB.bus(:,2);
        pv_to_pq_base(:,tt) = bus_typeB(pv0_idx) == 1;

    catch ME
        warning('runpf failed (baseline) at t=%d: %s', tt, ME.message);
        Vm_base(:,tt)=NaN; Va_base(:,tt)=NaN;
        genP_base(:,tt)=NaN; genQ_base(:,tt)=NaN;
        Gen_base(tt)=NaN; Load_base(tt)=NaN; Loss_base(tt)=NaN;
        satQmax_base(:,tt)=false; satQmin_base(:,tt)=false; pv_to_pq_base(:,tt)=false;
    end
end

% Baseline violations
viol_low_base  = false(nBus, config.nSteps);
viol_high_base = false(nBus, config.nSteps);
viol_low_base(nonSlack,:)  = Vm_base(nonSlack,:) < config.Vlow;
viol_high_base(nonSlack,:) = Vm_base(nonSlack,:) > config.Vhigh;

%% Deltas & summaries
t = 1:config.nSteps;
Vm_delta     = Vm_true(nonSlack,:) - Vm_base(nonSlack,:);  % attacked - baseline
rms_dev_true = sqrt(mean((Vm_true(nonSlack,:) - 1).^2, 1, 'omitnan'));
rms_dev_base = sqrt(mean((Vm_base(nonSlack,:) - 1).^2, 1, 'omitnan'));
meanV_true   = mean(Vm_true(nonSlack,:), 1, 'omitnan');
meanV_base   = mean(Vm_base(nonSlack,:), 1, 'omitnan');

%% ===================== COMPARATIVE PLOTS (SUBPLOTS) — GLOBAL LEGENDS =====================

% --- FDI: measured vs true at bus 5 (example, non-slack) ---
busFDI = 5;
figure('Name','FDI_Measured_vs_True_Bus5');
plot(t, Vm_true(busFDI,:), 'LineWidth',1.5); hold on;
plot(t, Vm_meas(busFDI,:), '--', 'LineWidth',1.5);
xlabel('Timestep');
ylabel('Voltage (p.u.)');
title(sprintf('FDI Attack: Measured vs True Voltage at Bus %d', busFDI));
grid on;
legend({'True V','Measured V (FDI-biased)'}, ...
       'Location','southoutside','Orientation','horizontal');

% 1) Selected Bus Voltages (True vs Baseline) — exclude slack from analysis
figure('Name','Selected Bus Voltages (True vs Baseline)');
tiledlayout(2,1,'TileSpacing','compact','Padding','compact');
bsel = [5 7 9];   % non-slack "victim" buses
labels_buses = arrayfun(@(b)sprintf('Bus %d',b), bsel,'UniformOutput',false);

ax1 = nexttile;
plot(t, Vm_true(bsel,:)', 'LineWidth', 1.6);
yline(config.Vlow,'--k'); yline(config.Vhigh,'--k');
title('Attacked Case'); xlabel('Timestep'); ylabel('Voltage (p.u.)');
grid on; shade_windows([1 config.nSteps], config);

ax2 = nexttile;
hBase = plot(t, Vm_base(bsel,:)', 'LineWidth', 1.6);
yline(config.Vlow,'--k'); yline(config.Vhigh,'--k');
title('Baseline (No Attack)'); xlabel('Timestep'); ylabel('Voltage (p.u.)');
grid on;

lg1 = legend(ax2, hBase, labels_buses, ...
    'Orientation','horizontal', 'NumColumns', numel(bsel));
lg1.Layout.Tile = 'south';

% 2) Voltage Heatmap (True vs Baseline vs Delta) — NON-SLACK buses only
figure('Name','Voltage Heatmap Comparison');
tiledlayout(3,1,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
imagesc(t, nonSlack, Vm_true(nonSlack,:)); set(ax1,'YDir','normal');
title('Attacked Voltages'); ylabel('Bus #');
colorbar(ax1); colormap(ax1,'parula');
shade_windows([1 config.nSteps], config);

ax2 = nexttile;
imagesc(t, nonSlack, Vm_base(nonSlack,:)); set(ax2,'YDir','normal');
title('Baseline: NO-ATTACK Voltages'); ylabel('Bus #');
colorbar(ax2); colormap(ax2,'parula');

ax3 = nexttile;
imagesc(t, nonSlack, Vm_delta); set(ax3,'YDir','normal');
title('\Delta Voltage (Attacked − Baseline)'); xlabel('Timestep'); ylabel('Bus #');
colorbar(ax3); colormap(ax3,'jet');

% fake handles for a panel legend (optional)
hold(ax3,'on');
hA = plot(ax3, nan,nan,'-','DisplayName','Attacked (TRUE)');
hB = plot(ax3, nan,nan,'-','DisplayName','Baseline');
hD = plot(ax3, nan,nan,'-','DisplayName','\Delta = Attacked − Baseline');
lg2 = legend([hA hB hD], 'Orientation','horizontal','NumColumns',3);
lg2.Layout.Tile = 'south';

% 3) RMS Voltage Deviation — NON-SLACK-based
figure('Name','RMS Voltage Deviation (True vs Baseline)');
tiledlayout(2,1,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
p1 = plot(t,rms_dev_true,'-m','LineWidth',1.8); hold on;
p2 = plot(find(anomaly),rms_dev_true(anomaly),'ro','MarkerFaceColor','r');
title('RMS Voltage Deviation – Attacked'); ylabel('Deviation (p.u.)');
grid on; shade_windows([1 config.nSteps], config);

ax2 = nexttile;
p3 = plot(t,rms_dev_base,'-c','LineWidth',1.8);
title('RMS Voltage Deviation – Baseline'); xlabel('Timestep'); ylabel('Deviation (p.u.)');
grid on;

lg3 = legend([p1 p2 p3], {'Attacked RMS','Anomaly flag','Baseline RMS'}, ...
            'Orientation','horizontal','NumColumns',3);
lg3.Layout.Tile = 'south';

% 4) Mean Voltage & Attack Timeline — NON-SLACK-based meanV
figure('Name','Mean Voltage & Attack Timeline');
tiledlayout(2,1,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
pMask = stairs(t, double(bitand(attack_mask,1)~=0) + ...
                  2*double(bitand(attack_mask,2)~=0) + ...
                  4*double(bitand(attack_mask,4)~=0), 'LineWidth',1.4);
title('Attack Timeline'); ylabel('Bitmask (1=DoS,2=DoD,4=FDI)'); grid on;

ax2 = nexttile;
pAtt = plot(t,meanV_true,'-k','LineWidth',1.5); hold on;
pBase= plot(t,meanV_base,'--k','LineWidth',1.2);
title('Mean Voltage (Non-Slack): Attacked vs Baseline'); xlabel('Timestep'); ylabel('Mean V (p.u.)');
grid on; shade_windows([1 config.nSteps], config);

lg4 = legend([pMask pAtt pBase], ...
    {'Attack bitmask','Mean V (Attacked)','Mean V (Baseline)'}, ...
    'Orientation','horizontal','NumColumns',3);
lg4.Layout.Tile = 'south';

% 5) Voltage Violations per Bus — NON-SLACK only
figure('Name','Voltage Violations Comparison');
tiledlayout(1,2,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
viol_attacked_counts = sum( (Vm_true(nonSlack,:)<config.Vlow) | ...
                            (Vm_true(nonSlack,:)>config.Vhigh), 2);
bA = bar(nonSlack, viol_attacked_counts, ...
         'FaceColor',[0.8 0.2 0.2]);
title('Attacked'); xlabel('Bus # (Non-Slack)'); ylabel('# Violations'); grid on;

ax2 = nexttile;
viol_base_counts = sum( (Vm_base(nonSlack,:)<config.Vlow) | ...
                        (Vm_base(nonSlack,:)>config.Vhigh), 2);
bB = bar(nonSlack, viol_base_counts, ...
         'FaceColor',[0.2 0.6 0.9]);
title('Baseline'); xlabel('Bus # (Non-Slack)'); grid on;

hold(ax2,'on');
dA = plot(ax2,nan,nan,'-','Color',[0.8 0.2 0.2],'LineWidth',6);
dB = plot(ax2,nan,nan,'-','Color',[0.2 0.6 0.9],'LineWidth',6);
lg5 = legend([dA dB], {'Attacked','Baseline'}, ...
    'Orientation','horizontal','NumColumns',2);
lg5.Layout.Tile = 'south';

% 6) Total Power Balance (Gen, Load, Loss) — system-wide
figure('Name','Power Balance Comparison');
tiledlayout(3,1,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
gA = plot(t,totalGenP,'-r','LineWidth',1.6); hold on;
gB = plot(t,Gen_base,'--r','LineWidth',1.2);
title('Total Generation'); ylabel('MW'); grid on; shade_windows([1 config.nSteps], config);

ax2 = nexttile;
lA = plot(t,totalLoadP,'-b','LineWidth',1.6); hold on;
lB = plot(t,Load_base,'--b','LineWidth',1.2);
title('Total Load'); ylabel('MW'); grid on;

ax3 = nexttile;
sA = plot(t,totalLoss,'-k','LineWidth',1.4); hold on;
sB = plot(t,Loss_base,'--k','LineWidth',1.2);
title('System Losses'); xlabel('Timestep'); ylabel('MW'); grid on;

lg6 = legend([gA gB lA lB sA sB], ...
    {'Gen (Attacked)','Gen (Baseline)', ...
     'Load (Attacked)','Load (Baseline)', ...
     'Loss (Attacked)','Loss (Baseline)'}, ...
    'Orientation','horizontal','NumColumns',3);
lg6.Layout.Tile = 'south';

% 7) Generator P & Q — global legend
figure('Name','Generator Active/Reactive Power Comparison');
tiledlayout(2,1,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
plot(t,genP','LineWidth',1.3); hold on;
plot(t,genP_base','--','LineWidth',1.1);
title('Generator P (MW): Attacked vs Baseline'); ylabel('MW'); grid on;
legend('Location','southoutside','Orientation','horizontal');

ax2 = nexttile;
plot(t,genQ','LineWidth',1.3); hold on;
plot(t,genQ_base','--','LineWidth',1.1);
title('Generator Q (MVAr): Attacked vs Baseline'); xlabel('Timestep'); ylabel('MVAr'); grid on;
legend('Location','southoutside','Orientation','horizontal');

% 8) PV→PQ Switching — global legend
figure('Name','PV→PQ Switching Comparison');
tiledlayout(2,1,'TileSpacing','compact','Padding','compact');

ax1 = nexttile;
imagesc(t,1:numel(pv0_idx),pv_to_pq); set(ax1,'YDir','normal');
colormap(ax1,flipud(gray)); colorbar(ax1);
title('Attacked PV→PQ Switching'); ylabel('PV bus idx');

ax2 = nexttile;
imagesc(t,1:numel(pv0_idx),pv_to_pq_base); set(ax2,'YDir','normal');
colormap(ax2,flipud(gray)); colorbar(ax2);
title('Baseline PV→PQ Switching'); xlabel('Timestep'); ylabel('PV bus idx');

hold(ax2,'on');
d1 = plot(ax2,nan,nan,'ks','MarkerFaceColor','k','LineWidth',1);
d0 = plot(ax2,nan,nan,'ks','MarkerFaceColor','w','LineWidth',1);
lg8 = legend([d1 d0], {'Switched (1)','Not switched (0)'}, ...
    'Orientation','horizontal','NumColumns',2);
lg8.Layout.Tile = 'south';

%% Quantitative Table Summary (NON-SLACK buses only for voltage metrics)

% Time Frames (logical masks)
t_DoS = bitand(attack_mask,1)~=0;
t_DoD = bitand(attack_mask,2)~=0;
t_FDI = bitand(attack_mask,4)~=0;

% Mean RMS Voltage Dev
m_rms_T   = mean(rms_dev_true, 'omitnan');
m_rms_B   = mean(rms_dev_base, 'omitnan');
m_rms_DoS = mean(rms_dev_true(t_DoS), 'omitnan');
m_rms_DoD = mean(rms_dev_true(t_DoD), 'omitnan');
m_rms_FDI = mean(rms_dev_true(t_FDI), 'omitnan');

% Max Voltage Dev
max_T   = max(rms_dev_true, [], 'all', 'omitnan');
max_B   = max(rms_dev_base, [], 'all', 'omitnan');
max_DoS = max(rms_dev_true(t_DoS), [], 'all', 'omitnan');
max_DoD = max(rms_dev_true(t_DoD), [], 'all', 'omitnan');
max_FDI = max(rms_dev_true(t_FDI), [], 'all', 'omitnan');

% Voltage Violation Count (NON-SLACK only)
viol_tot  = viol_low | viol_high;
viol_base = viol_low_base | viol_high_base;

viol_T   = sum(viol_tot(nonSlack,:),  'all');
viol_B   = sum(viol_base(nonSlack,:), 'all');
viol_DoS = sum(viol_tot(nonSlack,t_DoS), 'all');
viol_DoD = sum(viol_tot(nonSlack,t_DoD), 'all');
viol_FDI = sum(viol_tot(nonSlack,t_FDI), 'all');

% Mean MW Losses (system-wide)
loss_T   = mean(totalLoss, 'omitnan');
loss_B   = mean(Loss_base, 'omitnan');
loss_DoS = mean(totalLoss(t_DoS), 'omitnan');
loss_DoD = mean(totalLoss(t_DoD), 'omitnan');
loss_FDI = mean(totalLoss(t_FDI), 'omitnan');

% Base v True % Change (overall)
pct_rms  = (abs(m_rms_T  - m_rms_B) / max(m_rms_B,eps)) * 100;
pct_max  = (abs(max_T    - max_B)   / max(max_B,eps))   * 100;
pct_viol = (abs(viol_T   - viol_B)  / max(viol_B,1))    * 100;
pct_loss = (abs(loss_T   - loss_B)  / max(loss_B,eps))  * 100;

% Table Summary
Metric = { ...
    'RMS Voltage Deviation (avg p.u.)';
    'Max Voltage Deviation (p.u.)';
    'Voltage Violations (count, non-slack)';
    'Average System Losses (MW)'};

All_Attacks = [m_rms_T;  max_T;  viol_T;  loss_T];
DoS         = [m_rms_DoS;max_DoS;viol_DoS;loss_DoS];
DoD         = [m_rms_DoD;max_DoD;viol_DoD;loss_DoD];
FDI         = [m_rms_FDI;max_FDI;viol_FDI;loss_FDI];
Pct_Change  = [pct_rms;  pct_max; pct_viol; pct_loss];
tbl_sum = table(All_Attacks, DoS, DoD, FDI, Pct_Change, 'RowNames', Metric);
disp(tbl_sum);

%% --- SAVE FIGURES (PNGs + multi-page PDF) ---
outdir = fullfile(pwd, 'figs');
if ~exist(outdir, 'dir'); mkdir(outdir); end
figs = findall(0,'Type','figure');
try [~,ix] = sort([figs.Number]); figs = figs(ix); end %#ok<TRYNC>
for i = 1:numel(figs)
    f = figs(i);
    nm = get(f,'Name'); if isempty(nm), nm = sprintf('Figure_%02d', i); end
    nm = regexprep(nm, '\s+','_'); nm = regexprep(nm, '[^\w\-.]','-');
    filename = sprintf('%02d_%s.png', i, nm);
    full = fullfile(outdir, filename);
    try
        if exist('exportgraphics','file')
            exportgraphics(f, full, 'Resolution', 300);
        else
            set(f,'PaperPositionMode','auto'); print(f, full, '-dpng', '-r150');
        end
        fprintf('Saved: %s\n', full);
    catch ME
        warning('Failed saving %s: %s', full, ME.message);
    end
end
fprintf('Saved %d figure(s) to: %s\n', numel(figs), outdir);

outpdf = fullfile(outdir, 'All_Figures.pdf');
try
    if ~isempty(figs)
        if exist('exportgraphics','file')
            exportgraphics(figs(1), outpdf, 'Resolution', 300);
            for k = 2:numel(figs)
                exportgraphics(figs(k), outpdf, 'Append', true, 'Resolution', 300);
            end
        else
            set(figs(1),'PaperPositionMode','auto');
            print(figs(1), outpdf, '-dpdf', '-r150');
        end
        fprintf('Combined PDF saved: %s\n', outpdf);
    end
catch
    warning('Multi-page PDF export failed. PNGs are available in %s.', outdir);
end

%% --- LOCAL HELPER (for shading attack windows) ---
function shade_windows(xlims, config)
    yl = ylim; hold on;
    if ~isempty(config.DoS_times)
        patch([config.DoS_times(1) config.DoS_times(end) config.DoS_times(end) config.DoS_times(1)], ...
              [yl(1) yl(1) yl(2) yl(2)], [0.85 0.85 0.85], 'EdgeColor','none','FaceAlpha',0.3);
        text(config.DoS_times(1), yl(2), 'DoS', 'VerticalAlignment','top','FontWeight','bold');
    end
    if ~isempty(config.DoD_times)
        patch([config.DoD_times(1) config.DoD_times(end) config.DoD_times(end) config.DoD_times(1)], ...
              [yl(1) yl(1) yl(2) yl(2)], [0.90 0.90 1.00], 'EdgeColor','none','FaceAlpha',0.25);
        text(config.DoD_times(1), yl(2)*0.98, 'DoD', 'VerticalAlignment','top','FontWeight','bold');
    end
    if ~isempty(config.FDI_times)
        patch([config.FDI_times(1) config.FDI_times(end) config.FDI_times(end) config.FDI_times(1)], ...
              [yl(1) yl(1) yl(2) yl(2)], [1.00 0.90 0.90], 'EdgeColor','none','FaceAlpha',0.25);
        text(config.FDI_times(1), yl(2)*0.96, 'FDI', 'VerticalAlignment','top','FontWeight','bold');
    end
    xlim(xlims);
end
