filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;


% x = number of optimise
% y = number of optimise
% z = number of features
[x, y, z] = size(statistic);

noise = zeros(x);


for k=1:z
    for i=1:x
        len = 1;
        for j=1:y
            if statistic(i, j, k) > statistic(i, i, k)
                noise(i,len) = j;
                len = len + 1;
            end
        end
    end
end

%histogram(noise)

his = zeros(1,x);
for i=1:x
    his(i) = sum(noise(:) == i);
end


plot(1:x,his)
amount_of_problematic_functions = 0;
exlution_functions = zeros(1,x);
exlution_functions_size = 1;
for i=1:x
    if his(1,i) > 800
        exlution_functions(exlution_functions_size) = i;
        exlution_functions_size = exlution_functions_size + 1;
        amount_of_problematic_functions =amount_of_problematic_functions + 1;
    end
end

new_statistic = statistic;

for i=x:-1:1
	if ismember(i,exlution_functions)
       new_statistic(i, :, :) = [];
       new_statistic(:, i, :) = [];
	end
end



if ismember(314,his)
    disp('About to process data...');
end