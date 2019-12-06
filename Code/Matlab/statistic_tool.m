filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;

[x, y, z] = size(statistic);

for k=1:z
    for i=1:x
        for j=1:y
            if statistic(i,j,k)< statistic(j,i,k)
                statistic(i,j,k) = statistic(j,i,k);
            end
        end
    end
end

s = statistic(1:x,1:y,2);