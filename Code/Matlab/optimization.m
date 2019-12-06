filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;

% x = number of optimise
% y = number of optimise
% z = number of features
[x, y, z] = size(statistic);

V = zeros(x, z);

for i=1:x
    for k=1:z
        Vi = 0;
        for j=1:y
            Vi = Vi + statistic(i, j, k);
        end
        p = statistic(i, i, k) - (Vi  - statistic(i, i, k) );
        V(i, k) = p;
    end
end

C_min = -9999999999999999;
W_save = zeros(1, z);

for r=1:100000000000000000000
    W = rand_norm_array(z);
    
    S= W*V';
    C = min(S);
    
    if C > C_min
        C_min = C;
        W_save = W;
        disp("found new max C = " + C);
    end
end