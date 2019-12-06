filePath = 'C:\Users\User\Desktop\Final Project\Statistics\statistic.mat';
data = load(filePath);

statistic = data.statistic;


% x = number of optimise
% y = number of optimise
% z = number of features
[x, y, z] = size(statistic);


s = squeeze(statistic(1,1:5,:));%5
%s = statistic(1);%5
m = 1:z;
plot(m,s)
xlabel('x')
ylabel('sin(x)')
title('Plot of the Sine Function')