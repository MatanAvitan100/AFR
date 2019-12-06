function [norm_arr] = rand_norm_array(size)
    arr = rand(1, size);

    s = 0;
    for i=1:size
        s = s + arr(i);
    end
    norm_arr = arr / s; 
end

