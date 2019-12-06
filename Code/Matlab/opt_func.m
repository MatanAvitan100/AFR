
function [c,ceq] = opt_func(W)

    
    c = [];

    ceq = [ abs(W(1))-W(1), abs(W(2))-W(2),abs(W(3))-W(3),abs(W(4))-W(4),abs(W(5))-W(5),abs(W(6))-W(6),abs(W(7))-W(7),abs(W(8))-W(8)];
    