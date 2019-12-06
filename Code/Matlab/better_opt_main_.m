clear all;
filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;

% x = number of optimise
% y = number of optimise
% z = number of features
[x, y, z] = size(statistic);
z = z - 3;
S = zeros(x, y, z);
V = zeros(x, z);

%% Build V vector

for i=1:x % for each function
    for k=1:z
        ki = statistic(i, 1:y, k);
        V(i, k) = 4 * ki(i) +( z - 4) * sum(ki);
    end
end 

%% Doing optimization

fun = @(W)-1 * V * W;
options = optimoptions('fminimax', 'AbsoluteMaxObjectiveCount', 1, 'ConstraintTolerance', 5.3663e-19 );
w0 = zeros(z, 1);
ub = ones(z, 1);    % x <= 1
lb = zeros(z, 1);   % x >= 0
Aeq = ones(1, z);	% sum(x) == 1 constraint
beq = 1;
A = -V;
b = zeros(y, 1);
nonlcon = []; % @opt_func
W = fminimax(fun, w0, A, b, Aeq, beq, lb, ub, nonlcon, options);

%% Showing the result

if sum(W) ~= 1
    disp("Sum of W not equal to 1(" + sum(W) + ")")
end

C = min(V * W);

disp("Found C: " + C)
disp("Found W: " + W);

%% Testing the result

miss = 0;
hit = 0;

for i=1:x
	Pi_ = statistic(i, 1:y, 1:z);
    Xi = zeros(1, y);

    Pi = reshape(Pi_, y, z);
    Xi_ = Pi * W;
    
    sum_Xi_ = sum(Xi_);
    for j=1:y
            Xi(j) = Xi_(j) - (sum_Xi_ - Xi_(j));
    end
     
    if max(Xi) > Xi(i)
        % disp("Problematic function in row #" + i + ", The max is: " + max(Xi) + " and the Xi(i) is: " + Xi(i));
        miss = miss + 1;
    else
        % disp("Function " + i + " is ok, max(Xi) = " + max(Xi) + " min(Xi) = " + min(Xi));
        hit = hit + 1;
    end
   
end

disp("==== Total Statistics ====");
disp("AFR algorithm success rates: " + hit + " / " + x + " = " + hit/x + " %");
