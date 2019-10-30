package org.owasp.dependencycheck.utils;

import java.util.ArrayList;
import java.util.List;

public class HdivUtils {

	public HdivUtils() {
	}
	
	public interface Supplier<T> {
		T get();
	}
	
	public interface BiConsumer<T,U> {
		void accept(T t, U u);
	}
	
	public interface BinaryOperator<T> extends BiFunction<T, T, T> {
		
	}
	
	public interface BiFunction<T,U,R> {
		R apply(T t, U u);
	}
	
	public interface Function<T,R> {
		R apply(T t);
	}
	
	public interface Predicate<T> {
	    boolean test(T t);
	}
	
	public interface Collector<T, A, R> {
	    /**
	     * A function that creates and returns a new mutable result container.
	     *
	     * @return a function which returns a new, mutable result container
	     */
	    Supplier<A> supplier();

	    /**
	     * A function that folds a value into a mutable result container.
	     *
	     * @return a function which folds a value into a mutable result container
	     */
	    BiConsumer<A, T> accumulator();

	    /**
	     * A function that accepts two partial results and merges them.  The
	     * combiner function may fold state from one argument into the other and
	     * return that, or may return a new result container.
	     *
	     * @return a function which combines two partial results into a combined
	     * result
	     */
	    BinaryOperator<A> combiner();

	    /**
	     * Perform the final transformation from the intermediate accumulation type
	     * {@code A} to the final result type {@code R}.
	     *
	     * <p>If the characteristic {@code IDENTITY_TRANSFORM} is
	     * set, this function may be presumed to be an identity transform with an
	     * unchecked cast from {@code A} to {@code R}.
	     *
	     * @return a function which transforms the intermediate result to the final
	     * result
	     */
	    Function<A, R> finisher();

	}
	
	public static <T, K extends List<L>, L> List<T> collect(K input, Collector<L, ArrayList<T>, ArrayList<T>> collector) {
		ArrayList<T> container = collector.supplier().get();
		BiConsumer<ArrayList<T>, L> accumulator = collector.accumulator();
		for (L t : input) {
			accumulator.accept(container, t);
		}
		return (List<T>)container;
	}

	

}
