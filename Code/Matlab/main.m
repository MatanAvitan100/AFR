% Tested on Matlab 2019a

disp('About to process data...')

filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;
%statistic = new_statistic;

[x, y, z] = size(statistic);

%for k=1:z
%    for i=1:x
%        for j=1:y
%            if statistic(i,j,k)< statistic(j,i,k)
%                statistic(j,i,k) = statistic(i,j,k);
%            end
%        end
%    end
%end
kk =1:x;
num_of_features = 8;
random_save =  zeros(1, num_of_features);
hit_save = 0;

for r=1:1000000
    random = rand_norm_array(num_of_features); %(1-0).*rand(z,1) + 0;
    hit = 0;
    for i=1:x
        sum = zeros(1, y);

        max = 0;
        col = 0;

        for j=1:y%
            %for k=1:num_of_features
            sum(j) = sum(j) + (random(1) * statistic(i, j, 1));% Amount of menemonic match
            sum(j) = sum(j) + (random(2) * statistic(i, j, 2));% Mnemonic subsequence match
            sum(j) = sum(j) + (random(3) * statistic(i, j, 3));% Mnemonic match
            sum(j) = sum(j) + (random(4) * statistic(i, j, 4));%	
            sum(j) = sum(j) + (random(5) * statistic(i, j, 5));% Command rare match
            sum(j) = sum(j) + (random(6) * statistic(i, j, 6));% Jump match
            sum(j) = sum(j) + (random(7) * statistic(i, j, 7));% Nested function
            sum(j) = sum(j) + (random(8) * statistic(i, j, 8));% Constant match
            %end
        end

        for j=1:y
            if sum(1, j) > max
               max = sum(1, j);
               col = j;
            end 
        end

        if col == i
            hit = hit + 1;
        end
    end
    
    if hit > hit_save
            hit_save = hit;
            random_save = random;
    end
    disp(r);
end

