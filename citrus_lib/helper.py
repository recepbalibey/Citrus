from statsmodels.tsa.stattools import adfuller
import pandas as pd
from pyemd import emd, emd_samples
from scipy.stats import wasserstein_distance
from scipy.stats import ks_2samp

class Helper:

    def __init__(self):
        pass

    @staticmethod
    def mvariatetest(models):

        goodIPs = ['8.8.8.8', '1.0.0.1', '1.1.1.1']
        found = 0 #2 = found both good ip and whether multivariate

        foundMV = False
        foundGood = False

        mvariate = False
        for m in models:
            for k, v in m.items():
                
                if k.split("_")[1] == 'mprophet':
                    print("Model is multivariate, only need to compare 1 set of random variables")
                    mvariate = True
                    foundMV = True
                    
                if k.split("_")[0] in goodIPs and not foundGood:
                    foundGood = True
                    print("Found good IP")
                    goodIP = v
                    key = k.split("_")[0]
                    
            if foundGood and foundMV:
                break

            
        if goodIP is None:
            print("Could not find good IP model")
        return mvariate, goodIP, key

    @staticmethod
    def ks_distance(first, second):

        value, pvalue = ks_2samp(first, second)
        return value, pvalue

    #EMD Using sample values
    @staticmethod
    def distance(first, second):
        return wasserstein_distance(first, second)

    @staticmethod
    def add_regressor_to_future(future, regressors_df): 

        futures = future.copy() 
    
        futures.index = pd.to_datetime(futures.ds)
    
        regressors = pd.concat(regressors_df, axis=1)
    
        futures = futures.merge(regressors, left_index=True, right_index=True)
    
        futures = futures.reset_index(drop = True)
    
        return futures

    @staticmethod
    def add_regressor(data, regressor, varname=None): 
    
        data_with_regressors = data.copy()
    
        data_with_regressors.loc[:,varname] = regressor.loc[:,varname]
    
        return data_with_regressors

    @staticmethod
    def adftest(series):
        res = adfuller(series, autolag='AIC')
        p_value = res[1]
        return p_value

    @staticmethod
    def reverse_diff(df_forecast, df, nobs, ndiffs):

        for col in df.columns:

            if ndiffs == 1:
                df_forecast[str(col) + "_forecast"] = df[col].iloc[-nobs-1] + df_forecast[col].cumsum()
            elif ndiffs == 2:
                df_forecast[str(col) + "_1d"] = ( df[col].iloc[-nobs-1] - df[col].iloc[-nobs-2] ) + df_forecast[col].cumsum()
                df_forecast[str(col) + "_forecast"] = df[col].iloc[-nobs-1] + df_forecast[col + "_1d"].cumsum()
            elif ndiffs == 3:
                df_forecast[str(col) + "_2d"] = ( df[col].iloc[-nobs-1] - df[col].iloc[-nobs-2] - df[col].iloc[-nobs-3] ) + df_forecast[col].cumsum()
                df_forecast[str(col) + "_1d"] = ( df[col].iloc[-nobs-1] - df[col].iloc[-nobs-2] ) + df_forecast[col + "_2d"].cumsum()
                df_forecast[str(col) + "_forecast"] = df[col].iloc[-nobs-1] + df_forecast[col + "_1d"].cumsum()
            elif ndiffs == 0:
                df_forecast[str(col) + '_forecast'] = df_forecast[col]

            elif ndiffs > 3:
                print("no. diffs > 3 - implement")

        return df_forecast

    @staticmethod
    def diff_test(df):

        no_diffs = 0
        non_stationary = True

        df_diffed = df

        while non_stationary:

            triggered = False
            for col in df_diffed.columns:
                p_val = Helper.adftest(df_diffed[col])

                if p_val >= 0.05:
                    print(str(col) + " data is non-stationary")
                    triggered = True
                    break
                
            if triggered:
                no_diffs = no_diffs + 1
                df_diffed = df_diffed.diff().dropna()
            else:
                non_stationary = False

        print("DIFFS NEEDED = " + str(no_diffs))
        return [df_diffed, no_diffs]