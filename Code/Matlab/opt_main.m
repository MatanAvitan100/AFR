clear all;
filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;

% x = number of optimise
% y = number of optimise
% z = number of features
[x, y, z] = size(statistic);

S = zeros(x, y, z);
V = zeros(x, z);

%% Build S vector V(i, j, k) = Pij-(sum(Pij) - Pij)

for i=1:x
    for k=1:z
        Si = sum(statistic(i, :, k));
        for j=1:y
            p = statistic(i, j, k) - (Si  - statistic(i, j, k) );
            S(i, j, k) = p;
        end
    end
end 

%% Build V vector V(i, j) = Pij-(sum(Pij) - Pij)

for i=1:x
    for k=1:z
        Vi = sum(S(i, :, k));
        p = S(i, i, k) - (Vi  - S(i, i, k));
        V(i, k) = p;
    end
end

%% Doing optimization

fun = @(W)-1*W*V';
options = optimoptions('fminimax', 'AbsoluteMaxObjectiveCount', 1, 'ConstraintTolerance', 5.3663e-19 );
w0 = [1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
ub = ones(1, z);    % x <= 1
lb = zeros(1, z);   % x >= 0
Aeq = ones(1, z);	% sum(x) == 1 constraint
beq = 1;
nonlcon = []; % @opt_func
W = fminimax(fun, w0, [], [], Aeq, beq, lb, ub, nonlcon, options);

%% Showing the result

if sum(W) ~= 1
    disp("Sum of W not equal to 1(" + sum(W) + ")")
end

C = min(W*V');

disp("Found C: " + C)
disp("Found W: " + W);

%% Testing the result
 count = 0;
for i=1:x
	Pi_ = statistic(i, :, :);
    Xi = zeros(1, y);

    Pi = reshape(Pi_, y, z);
    Xi_ = W * Pi';
    
    sum_Xi_ = sum(Xi_);
    for j=1:y
            Xi(j) = Xi_(j) - (sum_Xi_ - Xi_(j)) - C;
    end
        
   
    if max(Xi) > Xi(i)
        %disp("Problematic function in row #" + i + ", The max is: " + max(Xi) + " and the Xi(i) is: " + Xi(i));
        count = count + 1;
    else
        %disp("Function " + i + " is ok, max(Xi) = " + max(Xi) + " min(Xi) = " + min(Xi));
    end
   
end
 disp(count)
